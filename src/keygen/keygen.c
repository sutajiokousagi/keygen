/*
 * Key generator for Chumby Falconwing
 * bunnie@chumby.com                   copyright (c) 2009 bunnie
 */

/*
 * Beecrypt Libarries:
 * Copyright (c) 2003 Bob Deblier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <time.h>

#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <beecrypt/beecrypt.h>
#include <beecrypt/rsa.h>

#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>

#define TESTING 0

/// public key of the AQS (testing, private key is known)
#if TESTING
#warning "USING TEST SERVER PUBLIC KEY"
static const char* rsa_n  = "BD9F9545D325639D2EA557D404C4FBB1F5EDEA28CEC1919F0668722DC25EECE5B1E8481EBBC371D02B8AE5BDE91665035B4DF9A25C462975126A06ABC14B6E0260CF19B2130779FCE8C121E7CEEBDF02A79C6AAE971A7AAC7428E49B6262487B35E35666FE5E751100DAA483EE92E9735B2DBAA52160088FAE869507BCAE87C2C8924C48A9461044B212951436F2B9E59FF4B266D555505CD9FE21787886B71E002F2CD927ACC8A924D399BE075635FB8092ED80F664A776CE5F64BC6BA49D3AB81E44B520E7629B58361E53F6C909C6460DB276294CB0FA0440B7775A28E13612C92A001BAF5E0345E39F7A1E5C2AF38ADF830C45C4D151F7C0B24C3ED82035";
static const char* rsa_e  = "00000029";
#else
/// public key of the AQS (permanent, private key is known by no man)
static const char* rsa_n  = "CC942A09714B30B2A5A704769563F70E5B5392D41DF185C59DCA7F152494AA626456EF2A298E9F6BF3515431AE78EB035967E69A8AC002A6C7EFE26CA6254218F5BF6D0482479A5E69AB50C1ECBBCA65F0C4E98127F8A5DFCEC34B4AF07D4347F58C589014CF52FE5D5EDCC18A30D17F9C81CB92500501E0AD8CC18CDBAE245FA2C314BB48C63591488A0D8CD379414857465EAFA4EE7C5B36C906022E4F623AED47EA8A92F91031C1CD7A40712ED2BCADA8D15469A9D04292849041109D104AE0608112849FD0910E1BDD95C34962E09D6F232A269459D33661045604A3AED5A57C39C346C0185A0131CBCB83E0A05D862980FFBCC9B0DEF8172BF629937A31";
static const char* rsa_e  = "00000029";
#endif

char SN[33];
char VERS[33];

#if defined(USE_ACCEL_ENTROPY) || defined(USE_FPGA_ENTROPY)
int i2c_file;
#endif

static int fd = 0;
static int *mem = 0;
static int *prev_mem_range = 0;

#define I2C_FILE_NAME "/dev/i2c-0"
#define USAGE_MESSAGE \
    "Usage:\n" \
    "  %s r [addr] [register] {[n]}  " \
        "to read value from [register]; if [n] is declared, reads [n] bytes\n" \
    "  %s w [addr] [register] [value]   " \
        "to write a value [value] to register [register]\n" \
    "  %s e [bytes]   " \
        "to read [bytes] entropy from the last bits of accelerometer axes.\n" \
    ""

static int set_i2c_register(int file,
                            unsigned char addr,
                            unsigned char reg,
                            unsigned char value) {

    unsigned char outbuf[2];
    struct i2c_rdwr_ioctl_data packets;
    struct i2c_msg messages[1];

    messages[0].addr  = addr;
    messages[0].flags = 0;
    messages[0].len   = sizeof(outbuf);
    messages[0].buf   = outbuf;

    /* The first byte indicates which register we'll write */
    outbuf[0] = reg;

    /* 
     * The second byte indicates the value to write.  Note that for many
     * devices, we can write multiple, sequential registers at once by
     * simply making outbuf bigger.
     */
    outbuf[1] = value;

    /* Transfer the i2c packets to the kernel and verify it worked */
    packets.msgs  = messages;
    packets.nmsgs = 1;
    if(ioctl(file, I2C_RDWR, &packets) < 0) {
        perror("Unable to send data");
        return 1;
    }

    return 0;
}


static int get_i2c_register(int file,
                            unsigned char addr,
                            unsigned char reg,
                            unsigned char *val,
                            int howmanybytes) {
    int i = 0;
    unsigned char inbuf[howmanybytes], outbuf, data = 0;
    struct i2c_rdwr_ioctl_data packets;
    struct i2c_msg messages[2];

    /*
     * In order to read a register, we first do a "dummy write" by writing
     * 0 bytes to the register we want to read from.  This is similar to
     * the packet in set_i2c_register, except it's 1 byte rather than 2.
     */
    outbuf = reg;
    messages[0].addr  = addr;
    messages[0].flags = 0;
    messages[0].len   = sizeof(outbuf);
    messages[0].buf   = &outbuf;

    /* The data will get returned in this structure */
    messages[1].addr  = addr;
    messages[1].flags = I2C_M_RD/* | I2C_M_NOSTART*/;
    messages[1].len   = sizeof(inbuf);
    messages[1].buf   = &inbuf;

    /* Send the request to the kernel and get the result back */
    packets.msgs      = messages;
    packets.nmsgs     = 2;
    if(ioctl(file, I2C_RDWR, &packets) < 0) {
        perror("Unable to send data");
        return 1;
    }
    
    //fprintf(stderr,"Returned:");
    for (i = 0; i < sizeof(inbuf); i++)
    {
        data = (data << 1) + (inbuf[i] & 1);
        //fprintf(stderr," %d",inbuf[i]);
    }
    //fprintf(stderr,"\n");

    *val = data;

    return 0;
}

int read_kernel_memory(long offset) {
    int result;

    // On falconwing, registers are located at 0xXXXXXXX0, the SET register
    // is located at 0xXXXXXXX4, the CLR register is at 0xXXXXXXX8, and the
    // TOG register is at 0xXXXXXXXC.  To set, clear, or toggle a bit,
    // write to the corresponding register.  These are write-only, so remap
    // reads to these registers on this platform to the root register.

    int *mem_range = (int *)(offset & ~0xFFFF);
    if( mem_range != prev_mem_range ) {
        prev_mem_range = mem_range;

        if(mem)
            munmap(mem, 0xFFFF);
        if(fd)
            close(fd);

        fd = open("/dev/mem", O_RDWR);
        if( fd < 0 ) {
            perror("Unable to open /dev/mem");
            fd = 0;
            return -1;
        }

        mem = mmap(0, 0xffff, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset&~0xFFFF);
        if( -1 == (int)mem ) {
            perror("Unable to mmap file");

            if( -1 == close(fd) )
                perror("Also couldn't close file");

            fd=0;
            return -1;
        }
    }

    int scaled_offset = (offset-(offset&~0xFFFF));
    result = mem[scaled_offset/sizeof(long)];

    return result;
}

int write_kernel_memory(long offset, long value) {
    int old_value = read_kernel_memory(offset);
    int scaled_offset = (offset-(offset&~0xFFFF));
    mem[scaled_offset/sizeof(long)] = value;
    return old_value;
}

void printmpNum(unsigned char *data, unsigned int size) {
  int i;

  for( i = 0; i < size; i+=4 ) {
    printf("%02X", data[i+3]);
    printf("%02X", data[i+2]);
    printf("%02X", data[i+1]);
    printf("%02X", data[i+0]);
    fflush(stdout);
  }
  printf( "\n" );
}

void fprintmpNum(unsigned char *data, unsigned int size, FILE *ofile) {
  int i;

  for( i = 0; i < size; i+=4 ) {
    fprintf(ofile, "%02X", data[i+3]);
    fprintf(ofile, "%02X", data[i+2]);
    fprintf(ofile, "%02X", data[i+1]);
    fprintf(ofile, "%02X", data[i+0]);
    fflush(ofile);
  }
  fprintf( ofile, "\n" );
}

unsigned int writempNum(unsigned char *data, unsigned int size, FILE *ofile ) {
  int i;
  unsigned int bytes = 0;

  for( i = 0; i < size; i+=4 ) {
    bytes += fwrite( &(data[i+3]), 1, 1, ofile);
    bytes += fwrite( &(data[i+2]), 1, 1, ofile);
    bytes += fwrite( &(data[i+1]), 1, 1, ofile);
    bytes += fwrite( &(data[i+0]), 1, 1, ofile);
  }
  fflush(ofile);

  return bytes;
}

unsigned int pad(unsigned int bytes, FILE *ofile) {
  int i;
  unsigned ret = 0;
  unsigned char c = 0x0; // pad to the fully programmed value so that ppl can't selectively inject data

  for( i = 0; i < bytes; i++ ) {
    ret += fwrite( &c, 1, 1, ofile);
  }

  return ret;
}

#if USE_ACCEL_ENTROPY 
#define ENTROPY_SAMPLES 4 // accelerometer is a much higher source of entropy
#elif defined(USE_FPGA_ENTROPY)
#define ENTROPY_SAMPLES (sizeof(unsigned long long)/8)
#else
#define ENTROPY_SAMPLES 128
#endif
int addEntropy(randomGeneratorContext *rngc) {
  unsigned long data = 0, odata;
  unsigned char bytes[4];
  int i;
  mpnumber myrn;
  unsigned int rec[ENTROPY_SAMPLES];
  unsigned int pool[ENTROPY_SAMPLES];
  int bytes_read = 0;
  int total = 0;

#if USE_ACCEL_ENTROPY
  int addr = 58;
  int reg = 6;
  unsigned char value;
  unsigned long x;
  int bits = 0;

  i = 0;
  while ( bytes_read < ENTROPY_SAMPLES )    {
      if(get_i2c_register(i2c_file, addr, reg, &value,3))
	{
	  fprintf(stderr,"Unable to get registers!\n");
	  break;
	}
      else {
	//	fprintf(stderr,"Byte returned: 0x%x, data: 0x%x\n",value,data);
	data = (data << 3) + value;
	bits += 3;
      }
      if ( bits > 32 )    /* Only output as bytes are formed. */
	{
	  rec[i] = data;
	  i++;
	  //	  printf( "record: %08x\n", rec[i - 1] );
	  //	  fputc(value, stdout);
	  bits = 0;
	  bytes_read++;
	}
      usleep(10000);
  }


#elif defined(USE_FPGA_ENTROPY)

  unsigned long long device_id = 0LL;
  unsigned char buffer;
  int addr = (0x3c>>1);
#define FPGA_DNA_ADR       0x38

  /* Code snagged from fpga_ctl.c's "n" command */
  for( i = 0; i < 7; i++ ) {
    get_i2c_register(i2c_file, addr, FPGA_DNA_ADR + i, &buffer, 1);
    device_id <<= 8;
    device_id |= (buffer & 0xFF);
  }

  memcpy(rec, &device_id, ENTROPY_SAMPLES);

  FILE *iwlist = popen("iwlist wlan0 scanning last", "r");
  char line_data[2048];
  if (!iwlist) {
    perror("Unable to open iwlist");
    return 1;
  }
  
  while( (bytes_read = read(fileno(iwlist), line_data, sizeof(line_data))) > 0)
    randomGeneratorContextSeed(rngc, line_data, bytes_read);
  pclose(iwlist);
  
#else


  FILE *arecord = popen("arecord -c 2 -f S16_LE -r 44100 -q", "r");
  if(!arecord) {
    perror("Unable to open arecord");
    return 1;
  }
  while( total < ENTROPY_SAMPLES ) {
    bytes_read = read(fileno(arecord), rec, sizeof(unsigned int) * ENTROPY_SAMPLES);
    if(bytes_read < 0) {
      perror("Unable to read bytes");
      return 1;
    }
    if(!bytes_read)
      continue;

    for( i = 0; i < (bytes_read >> 2); i++ ) {
      pool[total++] = rec[i];
    }
  }
  //  printf( "bytes read: %d\n", total );
  pclose(arecord);
#endif

  mpnzero(&myrn);
  mpnsize(&myrn, 4);
  data = 0;
  odata = 1;

  for( i = 0; i < ENTROPY_SAMPLES; i++ ) {

    //data = read_kernel_memory(0x8004c080);
    data = rec[i];
    //printf( "%08X ", data );

    if( data == odata ) {
      printf( "Warning: entropy source is repeating\n" );
    }
    odata = data;
    bytes[0] = (data & 0xFF);
    bytes[1] = (data & 0xFF00) >> 8;
    bytes[2] = (data & 0xFF0000) >> 16;
    bytes[3] = (data & 0xFF000000) >> 24;
    randomGeneratorContextSeed(rngc, bytes, 4);
    //    usleep(1000); // sleep for 1 millisecond, only used when live sampling data
    rngc->rng->next(rngc->param, (byte*) myrn.data, MP_WORDS_TO_BYTES(myrn.size)); 
  }

  return 0;
}

#define TESTRNG 0

#define NUM_PCC 21              // number of private keys to be generated
#define PRIVKEY_BITS 1024       // number of bits in the private key
#define PRIVKEY_REC_SIZE 0x200  // pad to this size for the private key record
#define NUM_OK  28             // number of OKs to generate

int main(int argc, char **argv)
{
  int failures = 0;
  
  rsakp keypair;
  mpnumber m, cipher, decipher;
  randomGeneratorContext rngc;
  int i = 0;
  mpnumber pid;
  mpnumber guid;
  mpnumber *pidPtr = &pid;
  mpnumber sn;
  int key = 0;
  FILE *ofile;
  FILE *pkeyFile;
  FILE *pkeyPacked;
  time_t now, rfc2440_time;
  unsigned long elapsed;
  struct tm base_tm;
  unsigned int bytes = 0;
  unsigned int data;

  mpnzero(&m);
  mpnzero(&cipher);
  mpnzero(&decipher);
  mpnzero(&pid);
  mpnzero(&guid);
  mpnzero(&sn);

  if( argc < 3 ) {
    printf( "Usage: keygen SN VERS\n" );
#if TESTING
    printf( "Warning! Using test defaults.\n" );
    strcpy(SN,   "00000000000000000000000000000108"); // need to extract serial number from hardware ID
    strcpy(VERS, "0004000A000000000000000000000000" );   // version 10.4 -- falconwing v4
#else
    exit(0);
#endif
  } else {
    for( i = 0; i < 32 - strlen(argv[1]); i++ )
      SN[i] = '0';
    strcpy(&SN[i],   argv[1]);

    for( i = 0; i < 32 - strlen(argv[2]); i++ )
      VERS[i] = '0';
    strcpy(&VERS[i], argv[2]);
  }
  
#if TESTING
  printf( "WARNING: Using the test AQS public key. Hit enter to continue\n" );
  getchar();
#else
  printf( "Using the production AQS public key.\n" );
#endif

  base_tm.tm_sec = 0;
  base_tm.tm_min = 0;
  base_tm.tm_hour = 0;
  base_tm.tm_mday = 1;
  base_tm.tm_mon = 0;
  base_tm.tm_year = 70;
  base_tm.tm_wday = 4;
  base_tm.tm_yday = 0;
  base_tm.tm_isdst = 0;
  rfc2440_time = mktime(&base_tm);
  //printf( "Time offsest computed from %s", ctime(&rfc2440_time) );
  now = time(NULL);
  elapsed = (unsigned long) difftime(now, rfc2440_time);
  printf( "Current time offset in seconds since epoch: %d\n", elapsed );

  ofile = fopen( "/tmp/keyfile", "wb" );
  if( ofile == NULL ) {
    printf( "Can't open keyfile for writing\n" );
    exit(-1);
  }

  pkeyFile = fopen( "/tmp/keyfile.pub", "wb" );
  if( pkeyFile == NULL ) {
    printf( "Can't open keyfile.pub for writing\n" );
  }

  pkeyPacked = fopen( "/tmp/keyfile.pub.bin", "wb" );
  if( pkeyPacked == NULL ) {
    printf( "Can't open keyfile.pub.bin for writing\n" );
  }

#if defined(USE_ACCEL_ENTROPY) || defined(USE_FPGA_ENTROPY)
  // Open a connection to the I2C userspace control file.
  if ((i2c_file = open(I2C_FILE_NAME, O_RDWR)) < 0) {
    perror("Unable to open i2c control file");
    exit(1);
  }
#endif

  if (randomGeneratorContextInit(&rngc, randomGeneratorDefault()) == 0)
    {
#if TESTRNG
      while(1) {
	mpnsize(&pid, 4);
	rngc.rng->next(rngc.param, (byte*) pid.data, MP_WORDS_TO_BYTES(pid.size)); 
	bytes += writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), ofile );
      }
#endif
      // generate SN field
      mpnsize(&sn, 4);
      mpnsethex(&sn, SN);

      // well, at least make sure the numbers are *unique*
      randomGeneratorContextSeed(&rngc, (unsigned char *)sn.data, MP_WORDS_TO_BYTES(sn.size));
      data = read_kernel_memory(0x8001c090); // extract data from the "high entropy seed"
      randomGeneratorContextSeed(&rngc, (unsigned char *) &data, 4); // so not portable

      addEntropy(&rngc);
      addEntropy(&rngc);

      // generate ID field
      mpnsize(&guid, 4);
      rngc.rng->next(rngc.param, (byte*) guid.data, MP_WORDS_TO_BYTES(guid.size)); 
      //printf( "id.size %d\n", MP_WORDS_TO_BYTES(guid.size) );
      fprintf( pkeyFile, "GUID:0:" ); fprintmpNum( (unsigned char *)guid.data, MP_WORDS_TO_BYTES(guid.size), pkeyFile );
      writempNum((unsigned char *)guid.data, MP_WORDS_TO_BYTES(guid.size), pkeyPacked );

      //printf( "sn.size %d\n", MP_WORDS_TO_BYTES(sn.size) );
      fprintf( pkeyFile, "SN:0:" ); fprintmpNum( (unsigned char *)sn.data, MP_WORDS_TO_BYTES(sn.size), pkeyFile );
      writempNum( (unsigned char *)sn.data, MP_WORDS_TO_BYTES(sn.size), pkeyPacked );

      // generate HW ver field
      mpnsize(&pid, 4);
      mpnsethex(&pid, VERS);
      //printf( "vers.size %d\n", MP_WORDS_TO_BYTES(pid.size) );
      fprintf( pkeyFile, "VERS:0:" ); fprintmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), pkeyFile );
      writempNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), pkeyPacked );
      
      printf( "Generating private keys" );
      fflush(stdout);
      for( key = 0; key < NUM_PCC; key++ ) {
	printf( "." );
	fflush(stdout);
	addEntropy(&rngc); // add entropy every time through the loop

	rsakpInit(&keypair);
	bytes = 0;
	mpnsize(&pid, 4);
	rngc.rng->next(rngc.param, (byte*) pid.data, MP_WORDS_TO_BYTES(pid.size)); 
     
	//printf( "pid.size %d\n", MP_WORDS_TO_BYTES(pid.size) );
	//printf( "key ID: " ); printmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size) );
	fprintf( pkeyFile, "PKEY_ID:%d:", key ); fprintmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), pkeyFile );
	bytes += writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), ofile );
	writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), pkeyPacked );

	rsakpMake(&keypair, &rngc, PRIVKEY_BITS);
	printf( "." );
	fflush(stdout);
	fprintf( stderr, "." );
	fflush(stderr);

	//printf( "p.size %d\n", MP_WORDS_TO_BYTES(keypair.p.size) );
	//printf( "p: " ); printmpNum( (unsigned char *)keypair.p.modl, MP_WORDS_TO_BYTES(keypair.p.size) );
	bytes += writempNum((unsigned char *)keypair.p.modl, MP_WORDS_TO_BYTES(keypair.p.size), ofile );

	//printf( "q.size %d\n", MP_WORDS_TO_BYTES(keypair.q.size) );
	//printf( "q: " ); printmpNum( (unsigned char *)keypair.q.modl, MP_WORDS_TO_BYTES(keypair.q.size) );
	bytes += writempNum((unsigned char *)keypair.q.modl, MP_WORDS_TO_BYTES(keypair.q.size), ofile );

	//printf( "dp.size %d\n", MP_WORDS_TO_BYTES(keypair.dp.size) );
	//printf( "dp:" );  printmpNum( (unsigned char *)keypair.dp.data, MP_WORDS_TO_BYTES(keypair.dp.size) );
	bytes += writempNum((unsigned char *)keypair.dp.data, MP_WORDS_TO_BYTES(keypair.dp.size), ofile );

	//printf( "dq.size %d\n", MP_WORDS_TO_BYTES(keypair.dq.size) );
	//printf( "dq:" );  printmpNum( (unsigned char *)keypair.dq.data, MP_WORDS_TO_BYTES(keypair.dq.size) );
	bytes += writempNum((unsigned char *)keypair.dq.data, MP_WORDS_TO_BYTES(keypair.dq.size), ofile );

	//printf( "qi.size %d\n", MP_WORDS_TO_BYTES(keypair.qi.size) );
	//printf( "qi:" );  printmpNum( (unsigned char *)keypair.qi.data, MP_WORDS_TO_BYTES(keypair.qi.size) );
	bytes += writempNum((unsigned char *)keypair.qi.data, MP_WORDS_TO_BYTES(keypair.qi.size), ofile );

	fprintf( pkeyFile, "PKEY_N:%d:", key ); fprintmpNum( (unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size), pkeyFile );
	//printf( "n.size %d\n", MP_WORDS_TO_BYTES(keypair.n.size) );
	//printf( "n: " );  printmpNum( (unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size) );
	bytes += writempNum((unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size), ofile );
	writempNum((unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size), pkeyPacked );

	fprintf( pkeyFile, "PKEY_E:%d:", key ); fprintmpNum( (unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size), pkeyFile );	//printf( "e.size %d\n", MP_WORDS_TO_BYTES(keypair.e.size) );
	//printf( "e:" );  printmpNum( (unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size) );
	bytes += writempNum((unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size), ofile );
	writempNum((unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size), pkeyPacked );

	now = time(NULL);
	elapsed = (unsigned long) difftime(now, rfc2440_time);
	//printf( "creation time in seconds: %d\n", elapsed );
	bytes += writempNum((unsigned char *)&elapsed, 4, ofile );

	// add padding here
	if( bytes < PRIVKEY_REC_SIZE )
	  pad( PRIVKEY_REC_SIZE - bytes, ofile );
	else
	  printf( "Error: number of bytes written exceeds record length.\n" );

	rsakpFree(&keypair);
      }
      printf( "\n" );


      // commit ID field
      printf( "GUID: " ); printmpNum( (unsigned char *)guid.data, MP_WORDS_TO_BYTES(guid.size) );
      bytes += writempNum((unsigned char *)guid.data, MP_WORDS_TO_BYTES(guid.size), ofile );

      // generate SN field
      printf( "SN:   " ); printmpNum( (unsigned char *)sn.data, MP_WORDS_TO_BYTES(sn.size) );
      bytes += writempNum((unsigned char *)sn.data, MP_WORDS_TO_BYTES(sn.size), ofile );

      // generate HW ver field
      mpnsize(&pid, 4);
      mpnsethex(&pid, VERS);
      //printf( "vers.size %d\n", MP_WORDS_TO_BYTES(pid.size) );
      printf( "VERS: " ); printmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size) );
      bytes += writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), ofile );
      
      for( key = 0; key < NUM_OK; key++ ) {
	addEntropy(&rngc); // add entropy every time through the loop
	mpnsize(&pid, 4);
	rngc.rng->next(rngc.param, (byte*) pid.data, MP_WORDS_TO_BYTES(pid.size)); 
	//printf( "OK.size %d\n", MP_WORDS_TO_BYTES(pid.size) );
	//printf( "OK%02d: ", key ); printmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size) );
	bytes += writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), ofile );
      }

      rsakpInit(&keypair);
      mpbsethex(&keypair.n, rsa_n);
      mpnsethex(&keypair.e, rsa_e);
      //printf( "AQS n.size %d\n", MP_WORDS_TO_BYTES(keypair.n.size) );
      //printf( "n: " );  printmpNum( (unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size) );
      bytes += writempNum((unsigned char *)keypair.n.modl, MP_WORDS_TO_BYTES(keypair.n.size), ofile );

      //printf( "AQS e.size %d\n", MP_WORDS_TO_BYTES(keypair.e.size) );
      //printf( "e:" );  printmpNum( (unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size) );
      bytes += writempNum((unsigned char *)keypair.e.data, MP_WORDS_TO_BYTES(keypair.e.size), ofile );
      //      pad( 256 + 4, ofile ); // pad out the AQS public keys for now
      rsakpFree(&keypair);
      
      for( key = 0; key < 16; key++ ) {
	addEntropy(&rngc); // add entropy every time through the loop
	mpnsize(&pid, 4);
	rngc.rng->next(rngc.param, (byte*) pid.data, MP_WORDS_TO_BYTES(pid.size)); 
	//printf( "entropy.size %d\n", MP_WORDS_TO_BYTES(pid.size) );
	//printf( "entropy%02d: ", key ); printmpNum( (unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size) );
	bytes += writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), ofile );
      }

    }
  
  // generate AES key
  printf( "Note that keyfile.pub.bin has AES key in it, should never write to disk: put it in /tmp.\n" );
  printf( "Disk does not sanitize data sufficiently upon erasure for security.\n" );
  mpnsize(&pid, 4);
  rngc.rng->next(rngc.param, (byte*) pid.data, MP_WORDS_TO_BYTES(pid.size)); 
  writempNum((unsigned char *)pid.data, MP_WORDS_TO_BYTES(pid.size), pkeyPacked );

  fclose(ofile);

  return 0;
}

/*
This program is hereby placed into the public domain.
Of course the program is provided without warranty of any kind.
*/
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

/*
  this program can read 24C16 (and probably smaller ones, too)
  I wrote it as a quick and dirty hack because my satellite receiver
  hung again... so I had to reprogram the eeprom where is stores it's
  settings.
 */

#define DEFAULT_I2C_BUS      "/dev/i2c-0"
#define DEFAULT_EEPROM_ADDR  0xA2         /* the 24C16 sits on i2c address 0x50 */
#define DEFAULT_NUM_PAGES    64           /* we default to a 24C16 eeprom which has 8 pages */
#define BYTES_PER_PAGE       256          /* one eeprom page is 256 byte */
#define MAX_BYTES            16            /* max number of bytes to write in one chunk */
       /* ... note: 24C02 and 24C01 only allow 8 bytes to be written in one chunk.   *
        *  if you are going to write 24C04,8,16 you can change this to 16            */

/* write len bytes (stored in buf) to eeprom at address addr, page-offset offset */
/* if len=0 (buf may be NULL in this case) you can reposition the eeprom's read-pointer */
/* return 0 on success, -1 on failure */
int eeprom_write(int fd,
		 unsigned int addr,
		 unsigned int offset,
		 unsigned char *buf,
		 unsigned char len
){
	struct i2c_rdwr_ioctl_data msg_rdwr;
	struct i2c_msg             i2cmsg;
	int i;
	char _buf[MAX_BYTES + 2];

	if(len>MAX_BYTES){
	    fprintf(stderr,"I can only write MAX_BYTES bytes at a time!\n");
	    return -1;
	}

	//	printf( "offset: %x\n", offset );
	if(len+offset > 0x4000){
	    fprintf(stderr,"Sorry, len(%d)+offset(%d) > 0x4000 (rom size)\n",
			len,offset);
	    return -1;
	}

	_buf[0] = (offset>>8) & 0x3f;
	_buf[1] = (offset   ) & 0xff;
	//	_buf[0]=offset;    /* _buf[0] is the offset into the eeprom page! */
	for(i=0;i<len;i++) /* copy buf[0..n] -> _buf[1..n+1] */
	    _buf[2+i]=buf[i];

	msg_rdwr.msgs = &i2cmsg;
	msg_rdwr.nmsgs = 1;

	i2cmsg.addr  = addr;
	i2cmsg.flags = 0;
	i2cmsg.len   = 2+len;
	i2cmsg.buf   = _buf;
	
#if 0
	for( i = 0; i < (2 + len); i++ ) {
	  if( (i % 16) == 0 ) {
	    printf( "\n%04x: ", i );
	  }
	  printf( "%02x ", _buf[i] );
	}
#endif

	if((i=ioctl(fd,I2C_RDWR,&msg_rdwr))<0){
	    perror("ioctl()");
	    fprintf(stderr,"ioctl returned %d\n",i);
	    return -1;
	}

	if(len>0) {
	  //	  fprintf(stderr,"Wrote %d bytes to eeprom at 0x%02x, offset %08x\n", len,addr,offset);
	  fprintf(stderr, ".");
	}
	//	else
	//	    fprintf(stderr,"Positioned pointer in eeprom at 0x%02x to offset %08x\n",
	//		    addr,offset);

	return 0;
}

/* read len bytes stored in eeprom at address addr, offset offset in array buf */
/* return -1 on error, 0 on success */
int eeprom_read(int fd,
		 unsigned int addr,
		 unsigned int offset,
		 unsigned char *buf,
		 unsigned char len
){
	struct i2c_rdwr_ioctl_data msg_rdwr;
	struct i2c_msg             i2cmsg;
	int i;

	if(len>MAX_BYTES){
	    fprintf(stderr,"I can only write MAX_BYTES bytes at a time!\n");
	    return -1;
	}

	if(eeprom_write(fd,addr,offset,NULL,0)<0)
	    return -1;

	msg_rdwr.msgs = &i2cmsg;
	msg_rdwr.nmsgs = 1;

	i2cmsg.addr  = addr;
	i2cmsg.flags = I2C_M_RD;
	i2cmsg.len   = len;
	i2cmsg.buf   = buf;

	if((i=ioctl(fd,I2C_RDWR,&msg_rdwr))<0){
	    perror("ioctl()");
	    fprintf(stderr,"ioctl returned %d\n",i);
	    return -1;
	}

	//	fprintf(stderr,"Read %d bytes from eeprom at 0x%02x, offset %08x\n",
	//		len,addr,offset);
	fprintf( stderr, "." );

	return 0;
}



int main(int argc, char **argv){
    int i,j;

    /* filedescriptor and name of device */
    int d; 
    char *dn=DEFAULT_I2C_BUS;

    /* filedescriptor and name of data file */
    int f=-1;
    char *fn=NULL;

    unsigned int addr=DEFAULT_EEPROM_ADDR;
    int rwmode=0;
    int pages=DEFAULT_NUM_PAGES;

    int force=0; /* suppress warning on write! */

    FILE *keyf;
    FILE *pkgf;
    unsigned char bytes[0x4000];
    int verbose = 0;
    int verify = 0;
    int passed = 1;
    
    while((i=getopt(argc,argv,"d:a:p:wyf:h:vk"))>=0){
	switch(i){
	case 'h':
	    fprintf(stderr,"%s [-d dev] [-a adr] [-p pgs] [-w keyfile package] [-y] [-f file]\n",argv[0]);
	    fprintf(stderr,"\tdev: device, e.g. /dev/i2c-0    (def)\n");
	    fprintf(stderr,"\tadr: base address of eeprom, eg 0xA0 (def)\n");
	    fprintf(stderr,"\tpgs: number of pages to read, eg 8 (def)\n");
	    fprintf(stderr,"\t-w : write to eeprom (default is reading!)\n");
	    fprintf(stderr,"\t-y : suppress warning when writing (default is to warn!)\n");
	    fprintf(stderr,"\t-f file: copy eeprom contents to/from file\n");
	    fprintf(stderr,"\t         (default for read is test only; for write is all zeros)\n");
	    fprintf(stderr,"\t-v : print blocks of data that are read\n");
	    fprintf(stderr,"\t-k : don't write, just do a verify dry run\n");
	    fprintf(stderr,"Note on pages/addresses:\n");
	    fprintf(stderr,"\teeproms with more than 256 byte appear as if they\n");
	    fprintf(stderr,"\twere several eeproms with consecutive addresses on the bus\n");
	    fprintf(stderr,"\tso we might as well address several seperate eeproms with\n");
	    fprintf(stderr,"\tincreasing addresses....\n\n");
	    exit(1);
	    break;
	case 'd':
	    dn=optarg;
	    break;
	case 'a':
	    if(sscanf(optarg,"0x%x",&addr)!=1){
		fprintf(stderr,"Cannot parse '%s' as addrs., example: 0xa0\n",
			optarg);
		exit(1);
	    }
	    break;
	case 'p':
	    if(sscanf(optarg,"%d",&pages)!=1){
		fprintf(stderr,"Cannot parse '%s' as number of pages, example: 8\n",
			optarg);
		exit(1);
	    }
	    break;
	case 'w': {
	  rwmode++;
	}
	    break;
	case 'f':
	    fn=optarg;
	    break;
	case 'y':
	    force++;
	    break;
	case 'v':
	  verbose = 1;
	  break;
	case 'k':
	  verify = 1;
	  break;
	}

    }
   
    fprintf(stderr,"base-address of eeproms       : 0x%02x\n",addr);
    fprintf(stderr,"number of pages to read       : %d (0x%02x .. 0x%02x)\n",
		    pages,addr,addr+pages-1);

    if(fn){
      if(!rwmode) { /* if we are reading, *WRITE* to file */
	    f=open(fn,O_WRONLY|O_CREAT,0666);
	//	else /* if we are writing to eeprom, *READ* from file */
	//	    f=open(fn,O_RDONLY);
	if(f<0){
	    fprintf(stderr,"Could not open data-file %s for reading or writing\n",fn);
	    perror(fn);
	    exit(1);
	}
	fprintf(stderr,"file opened for %7s       : %s\n",rwmode?"reading":"writing",fn);
	fprintf(stderr,"            on filedescriptor : %d\n",f);
      }
    }
    
    if( rwmode ) {
	  char *keyfile = argv[optind];
	  char *pkgfile = argv[optind+1];

	  if( (keyfile == NULL) || (pkgfile == NULL) )  {
	    printf( "Insufficient arguments to proceed.\n" );
	    return 1;
	  }
	  printf( "Writing cpid EEPROM with %s and %s\n", keyfile, pkgfile );
	  
	  if( (keyf = fopen(keyfile, "rb")) == NULL ) {
	    printf( "Can't open %s for reading.\n", keyfile );
	  }
	  if( (pkgf = fopen(pkgfile, "rb")) == NULL ) {
	    printf( "Can't open %s for reading.\n", pkgfile );
	  }
	  
	  for( i = 0; i < 0x4000; i++ ) {
	    bytes[i] = 0xFF;  // clear the array to default 1's
	  }

	  i = 0;
	  while( (i < 0x3000) && !feof(keyf)) { // first 12k is the key file
	    bytes[i++] = (unsigned char) fgetc(keyf);
	  }
	  if( i == 0x3000 ) {
	    printf( "Keyfile is too large! Aborting.\n" );
	    return 1;
	  }
	  i = 0x3000;
	  while( (i < 0x4000) && !feof(pkgf)) { // last 4k is the package
	    bytes[i++] = (unsigned char) fgetc(pkgf);
	  }
	  if( i == 0x4000 ) {
	    printf( "Package is too large! Aborting\n" );
	    return 1;
	  }
	  printf( "Read total of %d bytes\n", i );
    }

    if((d=open(dn,O_RDWR))<0){
	fprintf(stderr,"Could not open i2c at %s\n",dn);
	perror(dn);
	exit(1);
    }

    fprintf(stderr,"i2c-devicenode is             : %s\n",dn);
    fprintf(stderr,"            on filedescriptor : %d\n\n",d);

    /***
     *** I'm not the one to blame of you screw your computer!
     ***/
    if(rwmode && ! force){
      // hah hah.
    }

    // "bus warmup" -- why is this needed??
    i = 4;
    {
      unsigned char buf[BYTES_PER_PAGE];
      for(j=0;j<(BYTES_PER_PAGE/MAX_BYTES);j++)
	eeprom_read(d,addr,i*BYTES_PER_PAGE + j*MAX_BYTES,buf+(j*MAX_BYTES),MAX_BYTES);
      for(j=0;j<(BYTES_PER_PAGE/MAX_BYTES);j++)
	eeprom_read(d,addr,i*BYTES_PER_PAGE + j*MAX_BYTES,buf+(j*MAX_BYTES),MAX_BYTES);
    }

    for(i=0;i<pages;i++){
	unsigned char buf[BYTES_PER_PAGE];

	if(rwmode){
	  // write
	  //	  printf( "--------> writing <--------\n" );
	  if( !verify ) {
	    for(j=0;j<(BYTES_PER_PAGE/MAX_BYTES);j++) {
	      if(eeprom_write(d, addr, i*BYTES_PER_PAGE + j*MAX_BYTES, bytes+(j*MAX_BYTES)+i*BYTES_PER_PAGE, MAX_BYTES)<0) {
		printf( "error in writing.\n" );
		exit(1);
	      }
	      usleep(6000); // 5ms write cycle time per spec sheet, plus 1ms to grow on
	    }
	  } else {
	    // just read back and verify against our buffer
	    for(j=0;j<(BYTES_PER_PAGE/MAX_BYTES);j++) {
	      if(eeprom_read(d,addr,i*BYTES_PER_PAGE + j*MAX_BYTES,buf+(j*MAX_BYTES),MAX_BYTES)<0) 
		exit(1);
	      usleep(300);
	      {
		int k;
		int retries = 0;
		int correct = 1;
		do {
		  correct = 1;
		  for( k = 0; k < MAX_BYTES; k++ ) {
		    if( buf[j*MAX_BYTES + k] != bytes[j*MAX_BYTES + k + i*BYTES_PER_PAGE] ) {
		      correct = 0;
		    }
		  }
		  if( !correct ) { // reread
		    if(eeprom_read(d,addr,i*BYTES_PER_PAGE + j*MAX_BYTES,buf+(j*MAX_BYTES),MAX_BYTES)<0) 
		      exit(1);
		    usleep(300);
		    retries++;
		  }
		} while( !correct && retries < 4 );

		if( !correct ) {
		  printf("%04x +%02x -%02x\n", i*BYTES_PER_PAGE + j*MAX_BYTES + k, 
			 bytes[j*MAX_BYTES + k + i*BYTES_PER_PAGE], buf[j*MAX_BYTES + k] );
		  passed = 0;
		}
		if( retries > 0 )
		  fprintf( stderr, "%d", retries );
	      }
	    }
	  }
	} else {
	  // read
	  for(j=0;j<(BYTES_PER_PAGE/MAX_BYTES);j++) {
	    if(eeprom_read(d,addr,i*BYTES_PER_PAGE + j*MAX_BYTES,buf+(j*MAX_BYTES),MAX_BYTES)<0) 
	      exit(1);
	    usleep(300);
	  }
	}

	if( verbose ) {
	  for( j = 0; j < sizeof(buf); j++ ) {
	    if( (j % 16) == 0 ) {
	      printf( "\n%04x: ", j + i*BYTES_PER_PAGE );
	    }
	    if( !rwmode )
	      printf( "%02x ", buf[j] );
	    else
	      printf( "%02x ", bytes[j + i*BYTES_PER_PAGE] );
	  }
	}

	if(!rwmode && f>=0){
	    j=write(f,buf,sizeof(buf));
	    if(j!=sizeof(buf)){
		fprintf(stderr,"Cannot write to file '%s'\n",fn);
		perror(fn);
		exit(1);
	    }
	}

    }

    if( verify ) {
      if( passed ) {
	printf( "\nEEPROM contents verify correct\n" );
      } else {
	printf( "\nEEPROM contents failed to verify\n" );
      }
    }

    if(f>=0)
	close(f);

    close(d);

    exit(0);

}

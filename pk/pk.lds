OUTPUT_ARCH( "riscv" )

ENTRY( reset_vector )

SECTIONS
{

  /*--------------------------------------------------------------------*/
  /* Code and read-only segment                                         */
  /*--------------------------------------------------------------------*/

  /* Begining of code and text segment */
  . = 0x80000000;
  
	.header :
  {
    /* ## manufacturer_keys : */

    /* 8 Bytes : manufacturer meta/reserved */
    PROVIDE( sanctum_m_meta = .);
    . += 0x8;

    /* 32 Bytes : manufacturer public key */
    PROVIDE( sanctum_m_public_key = . );
    . += 0x20;

    /* ## device_keys : */

    /* 8 Bytes : device meta/reserved */
    PROVIDE( sanctum_dev_meta = . );
    . += 0x8;

    /* 16 Bytes : device PUF b */
    PROVIDE( sanctum_dev_puf_b = . );
    . += 0x10;

    /* 32 Bytes : device PUF e */
    PROVIDE( sanctum_dev_puf_e = . );
    . += 0x20;

    /* 32 Bytes : device PUF s */
    PROVIDE( sanctum_dev_puf_s = . );
    . += 0x20;

    /* 64 Bytes : device symmetric key */
    PROVIDE( sanctum_dev_symmetric_key = . );
    . += 0x40;

    /* 32 Bytes : device public key */
    PROVIDE( sanctum_dev_public_key = . );
		PROVIDE( PK_D = . );
    . += 0x20;

    /* 64 Bytes : device secret key */
    PROVIDE( sanctum_dev_secret_key = . );
    . += 0x40;

    /* 64 Bytes : device's signature by manufacturer */
    PROVIDE( sanctum_dev_signature = . );
    . += 0x40;

    /* ## security_monitor_keys : */

    /* 8 Bytes : security monitor meta/reserved */
    PROVIDE( sanctum_sm_meta = . );
    . += 0x8;

    /* 4 Bytes : security monitor size (bytes) */
    PROVIDE( sanctum_sm_size = . );
    /* LONG( ADDR(.payload) - ADDR( .text ) ); */

    /* 64 Bytes : security monitor hash */
    PROVIDE( sanctum_sm_hash = . );
		PROVIDE( SM_H = . );
    . += 0x40;

    /* 64 Bytes : security monitor symmetric key */
    PROVIDE( sanctum_sm_symmetric_key = . );
    . += 0x40;

    /* 32 Bytes : security monitor public key */
    PROVIDE( sanctum_sm_public_key = . );
		PROVIDE( PK_SM = . );
    . += 0x20;

    /* 64 Bytes : security monitor secret key */
    PROVIDE( sanctum_sm_secret_key = . );
		PROVIDE( SK_SM = . );
    . += 0x40;

    /* 64 Bytes : security monitor's signature by device */
    PROVIDE( sanctum_sm_signature = . );
		PROVIDE( SM_SIG = . );
    . += 0x40;
  }


_ftext = .;
  PROVIDE( eprol = . );

  .text :
  {
    *(.text.init)
  }

  /* text: Program code section */
  .text : 
  {
    *(.text)
    *(.text.*)
    *(.gnu.linkonce.t.*)
  }

  /* rodata: Read-only data */
  .rodata : 
  {
    *(.rdata)
    *(.rodata)
    *(.rodata.*)
    *(.gnu.linkonce.r.*)
  }

  /* End of code and read-only segment */
  PROVIDE( etext = . );
  _etext = .;

  /*--------------------------------------------------------------------*/
  /* HTIF, isolated onto separate page                                  */
  /*--------------------------------------------------------------------*/
  . = ALIGN(0x1000);
  .htif :
  {
    PROVIDE( __htif_base = . );
    *(.htif)
  }
  . = ALIGN(0x1000);

  /*--------------------------------------------------------------------*/
  /* Initialized data segment                                           */
  /*--------------------------------------------------------------------*/

  /* Start of initialized data segment */
  . = ALIGN(16);
   _fdata = .;

  /* data: Writable data */
  .data : 
  {
    *(.data)
    *(.data.*)
    *(.srodata*)
    *(.gnu.linkonce.d.*)
    *(.comment)
  }

  /* End of initialized data segment */
  . = ALIGN(4);
  PROVIDE( edata = . );
  _edata = .;

  /*--------------------------------------------------------------------*/
  /* Uninitialized data segment                                         */
  /*--------------------------------------------------------------------*/

  /* Start of uninitialized data segment */
  . = .;
  _fbss = .;

  /* sbss: Uninitialized writeable small data section */
  . = .;

  /* bss: Uninitialized writeable data section */
  . = .;
  _bss_start = .;
  .bss : 
  {
    *(.bss)
    *(.bss.*)
    *(.sbss*)
    *(.gnu.linkonce.b.*)
    *(COMMON)
  }

  _end = .;
}

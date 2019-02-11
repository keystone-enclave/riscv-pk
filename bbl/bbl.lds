OUTPUT_ARCH( "riscv" )

ENTRY( reset_vector )

SECTIONS
{
  . = 0x80000000; /* load starting at the beginning of DRAM */

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
    PROVIDE( __htif_base = .);
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

  .sbi :
  {
    *(.sbi)
  }

  /* # Sanctum params */
  /* ================ */
  . = 0x801ff000; /* the last page before the payload */

  /* ## manufacturer_keys : */

  /* 32 Bytes : manufacturer public key */
  PROVIDE( sanctum_m_public_key = . );
  . += 0x20;

  /* 32 Bytes : device public key */
  PROVIDE( sanctum_dev_public_key = . );
  . += 0x20;

  /* 64 Bytes : device secret key */
  PROVIDE( sanctum_dev_secret_key = . );
  . += 0x40;

  /* ## security_monitor_keys : */

  /* 64 Bytes : security monitor hash */
  PROVIDE( sanctum_sm_hash = . );
  . += 0x40;

  /* 32 Bytes : security monitor public key */
  PROVIDE( sanctum_sm_public_key = . );
  . += 0x20;

  /* 64 Bytes : security monitor secret key */
  PROVIDE( sanctum_sm_secret_key = . );
  . += 0x40;

  /* 64 Bytes : security monitor's signature by device */
  PROVIDE( sanctum_sm_signature = . );
  . += 0x40;

  . = ALIGN(0x1000);

  /* # Payload binary */
  /* ================ */
  .payload :
  {
    *(.payload)
  }

  _end = .;
}

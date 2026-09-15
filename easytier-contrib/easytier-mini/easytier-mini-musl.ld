SECTIONS
{
  .eh_frame :
  {
    KEEP(*crtbegin.o(.eh_frame))
    KEEP(*crtend.o(.eh_frame))
  }
  /DISCARD/ :
  {
    *(EXCLUDE_FILE (*crtbegin.o *crtend.o) .eh_frame)
    *(.eh_frame_hdr)
  }
}
INSERT AFTER .data;

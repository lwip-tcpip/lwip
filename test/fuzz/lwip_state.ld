/* Group mutable lwIP core/app state into one contiguous section so the
 * persistent-mode fuzzer can snapshot and restore it between inputs. */
SECTIONS {
  .lwip_state : ALIGN(64) {
    __lwip_state_start = .;
    *liblwipcommon.a:*(.data .data.* .bss .bss.* COMMON)
    *liblwipapps.a:*(.data .data.* .bss .bss.* COMMON)
    __lwip_state_end = .;
  }
}
INSERT BEFORE .data;

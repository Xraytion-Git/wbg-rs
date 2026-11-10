// build.rs — embed Wooting icon as PE resource.
// Creates a minimal COFF .o with .rsrc section and links it via gcc.
fn main() {
    println!("cargo:rerun-if-changed=wooting.ico");
    let ico = match std::fs::read("wooting.ico") {
        Ok(v) => v,
        Err(_) => { println!("cargo:warning=wooting.ico not found"); return; }
    };
    if ico.len() < 22 { return; }
    let img_off = u32::from_le_bytes([ico[18], ico[19], ico[20], ico[21]]) as usize;
    let img_sz = u32::from_le_bytes([ico[14], ico[15], ico[16], ico[17]]) as usize;
    if img_off + img_sz > ico.len() { return; }
    let img = &ico[img_off..img_off + img_sz];

    let out = std::env::var("OUT_DIR").unwrap();
    let obj_path = std::path::PathBuf::from(&out).join("icon.o");

    // Build a minimal COFF object with a .rsrc section containing
    // RT_ICON + RT_GROUP_ICON resources in PE resource directory format.
    let rsrc = build_pe_rsrc(img, &ico, img_sz);
    let coff = build_coff_obj(&rsrc);
    std::fs::write(&obj_path, &coff).unwrap();
    println!("cargo:rustc-link-arg={}", obj_path.display());
    println!("cargo:warning=PE icon COFF object linked ({} bytes)", coff.len());
}

fn build_pe_rsrc(img: &[u8], ico: &[u8], img_sz: usize) -> Vec<u8> {
    // PE resource directory: 3 levels (Type -> Name/Id -> Language -> Data)
    // Level 1: RT_GROUP_ICON (14) + RT_ICON (3)
    // Level 2: id=1 for each
    // Level 3: language=0x0409
    // Data entries: RT_ICON data = img bytes, RT_GROUP_ICON data = group dir

    let grp_data = build_grp_dir(ico, img_sz);

    // Layout:
    // [root dir: 2 entries]
    // [type dir for RT_GROUP_ICON: 1 entry]
    // [type dir for RT_ICON: 1 entry]
    // [name dir for grp id=1: 1 entry]
    // [name dir for icon id=1: 1 entry]
    // [lang dir for grp: 1 entry -> data entry]
    // [lang dir for icon: 1 entry -> data entry]
    // [data entry for grp]
    // [data entry for icon]
    // [grp data]
    // [icon data]

    // Simplify: use a flat structure that PE loader accepts.
    // Actually, let me just build the standard 3-level tree.

    let mut d: Vec<u8> = Vec::new();

    // We'll calculate offsets as we go.
    // Root dir: 2 entries (RT_GROUP_ICON=14, RT_ICON=3)
    // Each dir entry: 8 bytes (id:4 + offset:4)
    // Dir header: 16 bytes (chars:4 + time:4 + ver_major:2 + ver_minor:2 + num_named:2 + num_id:2)

    let dir_hdr = |named: u16, id: u16| -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
        v.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        v.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
        v.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
        v.extend_from_slice(&named.to_le_bytes());
        v.extend_from_slice(&id.to_le_bytes());
        v
    };

    let dir_entry = |id: u32, offset: u32| -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(&offset.to_le_bytes());
        v
    };

    // Calculate all offsets
    let root_sz = 16 + 2 * 8; // hdr + 2 entries
    let type_grp_sz = 16 + 1 * 8; // hdr + 1 entry
    let type_icon_sz = 16 + 1 * 8;
    let name_grp_sz = 16 + 1 * 8;
    let name_icon_sz = 16 + 1 * 8;
    let lang_grp_sz = 16 + 1 * 8;
    let lang_icon_sz = 16 + 1 * 8;
    let data_entry_sz = 16; // RVA + Size + Codepage + Reserved

    let off_root = 0u32;
    let off_type_grp = off_root + root_sz as u32;
    let off_type_icon = off_type_grp + type_grp_sz as u32;
    let off_name_grp = off_type_icon + type_icon_sz as u32;
    let off_name_icon = off_name_grp + name_grp_sz as u32;
    let off_lang_grp = off_name_icon + name_icon_sz as u32;
    let off_lang_icon = off_lang_grp + lang_grp_sz as u32;
    let off_data_grp = off_lang_icon + lang_icon_sz as u32;
    let off_data_icon = off_data_grp + data_entry_sz as u32;
    let off_grp_data = off_data_icon + data_entry_sz as u32;
    let off_icon_data = off_grp_data + grp_data.len() as u32;

    // Root directory
    d.extend_from_slice(&dir_hdr(0, 2));
    // RT_GROUP_ICON entry (id=14, high bit set for subdirectory)
    d.extend_from_slice(&dir_entry(14, 0x80000000 | off_type_grp));
    // RT_ICON entry (id=3)
    d.extend_from_slice(&dir_entry(3, 0x80000000 | off_type_icon));

    // Type dir for RT_GROUP_ICON
    d.extend_from_slice(&dir_hdr(0, 1));
    d.extend_from_slice(&dir_entry(1, 0x80000000 | off_name_grp));

    // Type dir for RT_ICON
    d.extend_from_slice(&dir_hdr(0, 1));
    d.extend_from_slice(&dir_entry(1, 0x80000000 | off_name_icon));

    // Name dir for grp id=1
    d.extend_from_slice(&dir_hdr(0, 1));
    d.extend_from_slice(&dir_entry(0x0409, 0x80000000 | off_lang_grp));

    // Name dir for icon id=1
    d.extend_from_slice(&dir_hdr(0, 1));
    d.extend_from_slice(&dir_entry(0x0409, 0x80000000 | off_lang_icon));

    // Lang dir for grp
    d.extend_from_slice(&dir_hdr(0, 1));
    d.extend_from_slice(&dir_entry(0, off_data_grp)); // data entry (no high bit)

    // Lang dir for icon
    d.extend_from_slice(&dir_hdr(0, 1));
    d.extend_from_slice(&dir_entry(0, off_data_icon));

    // Data entry for grp: RVA + Size + Codepage + Reserved
    // RVA is relative to section start — we'll adjust at link time
    d.extend_from_slice(&off_grp_data.to_le_bytes()); // RVA (relative to section)
    d.extend_from_slice(&(grp_data.len() as u32).to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes()); // Codepage
    d.extend_from_slice(&0u32.to_le_bytes()); // Reserved

    // Data entry for icon
    d.extend_from_slice(&off_icon_data.to_le_bytes());
    d.extend_from_slice(&(img.len() as u32).to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());

    // Group icon data
    d.extend_from_slice(&grp_data);

    // Icon data
    d.extend_from_slice(img);

    d
}

fn build_grp_dir(ico: &[u8], img_sz: usize) -> Vec<u8> {
    let mut g = Vec::new();
    g.extend_from_slice(&0u16.to_le_bytes()); // idReserved
    g.extend_from_slice(&1u16.to_le_bytes()); // idType = icon
    g.extend_from_slice(&1u16.to_le_bytes()); // idCount = 1
    g.push(ico[6]); g.push(ico[7]); g.push(ico[8]); g.push(ico[9]);
    g.extend_from_slice(&u16::from_le_bytes([ico[10], ico[11]]).to_le_bytes());
    g.extend_from_slice(&u16::from_le_bytes([ico[12], ico[13]]).to_le_bytes());
    g.extend_from_slice(&(img_sz as u32).to_le_bytes());
    g.extend_from_slice(&1u16.to_le_bytes()); // nID
    g
}

fn build_coff_obj(rsrc: &[u8]) -> Vec<u8> {
    // Minimal COFF object with one .rsrc section.
    // COFF header: 20 bytes
    // Section header: 40 bytes each
    // Section data
    let num_sections: u16 = 1;
    let timestamp: u32 = 0;
    let symtab_ptr: u32 = 0;
    let num_syms: u32 = 0;
    let opt_hdr_size: u16 = 0;
    let characteristics: u16 = 0x0104; // IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_LINE_NUMS_STRIPPED

    // Align section data to 4 bytes
    let mut data = rsrc.to_vec();
    while data.len() % 4 != 0 { data.push(0); }

    let hdr_size = 20u32;
    let sec_hdr_size = 40u32;
    let data_offset = hdr_size + sec_hdr_size;

    let mut obj = Vec::new();

    // COFF header
    obj.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine = AMD64
    obj.extend_from_slice(&num_sections.to_le_bytes());
    obj.extend_from_slice(&timestamp.to_le_bytes());
    obj.extend_from_slice(&symtab_ptr.to_le_bytes());
    obj.extend_from_slice(&num_syms.to_le_bytes());
    obj.extend_from_slice(&opt_hdr_size.to_le_bytes());
    obj.extend_from_slice(&characteristics.to_le_bytes());

    // Section header for .rsrc
    let mut name = [0u8; 8];
    name[..5].copy_from_slice(b".rsrc");
    obj.extend_from_slice(&name);
    obj.extend_from_slice(&(data.len() as u32).to_le_bytes()); // VirtualSize (same as raw)
    obj.extend_from_slice(&0u32.to_le_bytes()); // VirtualAddress
    obj.extend_from_slice(&(data.len() as u32).to_le_bytes()); // SizeOfRawData
    obj.extend_from_slice(&data_offset.to_le_bytes()); // PointerToRawData
    obj.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
    obj.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
    obj.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
    obj.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
    obj.extend_from_slice(&0x40000040u32.to_le_bytes()); // Characteristics: INIT_DATA | READ

    // Section data
    obj.extend_from_slice(&data);

    obj
}

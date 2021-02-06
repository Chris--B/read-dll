//! `syms` utility
//!
//! Read symbol information from DLLs, SOs, Dylibs, and o/obj object files.

// Useful list from:
// https://github.com/rust-unofficial/patterns/blob/master/anti_patterns/deny-warnings.md
#![deny(
    missing_debug_implementations,
    missing_copy_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_qualifications,
    unused_results
)]

use std::path::Path;

type Result<T, E = failure::Error> = std::result::Result<T, E>;

/// The format of a binary
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum BinaryKind {
    /// A PE file
    Pe,

    /// A Elf file
    Elf,

    /// A MacO file
    MachO,
}
/// Per-binary metadata that's unique to a specific format
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum BinaryExtra {
    /// Data unique to PE files
    #[non_exhaustive]
    Pe {
        /// optional header?
        optional_header: Option<goblin::pe::optional_header::OptionalHeader>,
    },

    /// Data unique to Elf files
    #[non_exhaustive]
    Elf {
        // None yet
    },

    /// Data unique to MachO files
    #[non_exhaustive]
    MachO {
        // None yet
    },
}

/// Per-symbol metadata that's unique to a specific format
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum SymbolExtra {
    /// Data unique to PE files
    #[non_exhaustive]
    Pe {
        // None yet
    },

    /// Data unique to Elf files
    #[non_exhaustive]
    Elf {
        // None yet
    },

    /// Data unique to MachO files
    #[non_exhaustive]
    MachO {
        // TODO: Detail export trie flags
        #[allow(missing_docs)]
        flags: u64,
    },
}

/// A single symbol exported from a binary
#[derive(Clone, Debug)]
pub struct Symbol {
    name:  String,
    extra: Option<SymbolExtra>,
}

impl Symbol {
    /// The raw name of an exported symbol
    pub fn mangled_name(&self) -> &str {
        &self.name
    }

    /// If the symbol name matches a C++ name-mangling pattern, this is the demangled name of an
    /// exported symbol
    pub fn demangled_name(&self) -> Option<String> {
        let flags = msvc_demangler::DemangleFlags::llvm();
        msvc_demangler::demangle(&self.name, flags).ok()
    }

    /// A name that identifiers this symbol
    pub fn name(&self) -> String {
        if let Some(name) = self.demangled_name() {
            name
        } else {
            self.name.to_string()
        }
    }

    /// Any extra meta-data that's unique to the specific format this symbol was loaded from
    pub fn extra(&self) -> Option<SymbolExtra> {
        self.extra
    }
}

#[derive(Clone, Debug)]
struct Binary {
    pub name:    Option<String>,
    pub kind:    BinaryKind,
    pub symbols: Vec<Symbol>,
    pub extra:   Option<BinaryExtra>,
}

impl Binary {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path: &Path = path.as_ref();
        let bytes = std::fs::read(path)?;

        Binary::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Binary::from_object(&goblin::Object::parse(bytes)?)
    }

    pub fn from_object(obj: &goblin::Object) -> Result<Self> {
        use goblin::Object::*;

        let bin = match obj {
            PE(ref pe) => Binary::from_pe(pe),
            Elf(ref elf) => Binary::from_elf(elf),
            Mach(ref mach) => {
                let bin: &Binary = &Binary::from_mach_archive(mach)?[0];
                bin.clone()
            },
            Unknown(magic) => {
                eprintln!("Unknown magic number {} (0x{:x})", magic, magic);
                failure::bail!("Unhandled object type: {:?}", Unknown(*magic))
            },
            obj => {
                failure::bail!("Unhandled object type: {:#?}", obj)
            },
        };

        Ok(bin)
    }
}

impl Binary {
    fn from_pe(pe: &goblin::pe::PE) -> Self {
        let symbols: Vec<_> = pe
            .exports
            .iter()
            .map(|export| {
                Symbol {
                    // PE libraries may export functions only by ordinal, so they
                    // don't have a name. Don't care, just make it
                    // empty instead.
                    name:  export.name.unwrap_or_default().to_string(),
                    extra: Some(SymbolExtra::Pe {}),
                }
            })
            .collect();

        let name = pe.name.map(str::to_string);
        let kind = BinaryKind::Pe;

        let extra = Some(BinaryExtra::Pe {
            optional_header: pe.header.optional_header,
        });


        Binary {
            name,
            kind,
            symbols,
            extra,
        }
    }

    fn from_elf(elf: &goblin::elf::Elf) -> Self {
        // See: http://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-vi.html
        let strings = &elf.dynstrtab;

        let symbols = elf
            .dynsyms
            .iter()
            .map(|dynsym| {
                Symbol {
                    name:  strings[dynsym.st_name].to_string(),
                    extra: None,
                }
            })
            .collect();

        Binary {
            name: elf.soname.map(str::to_string),
            kind: BinaryKind::Elf,
            symbols,
            extra: None,
        }
    }

    fn from_mach_binary(macho: &goblin::mach::MachO) -> Result<Self> {
        // See: https://adrummond.net/posts/macho

        let exports = macho.exports()?;
        let symbols: Vec<_> = exports
            .iter()
            .map(|export| {
                use goblin::mach::exports::ExportInfo::*;
                let flags = match export.info {
                    Regular { flags, .. } => flags,
                    Reexport { flags, .. } => flags,
                    Stub { flags, .. } => flags,
                };

                Symbol {
                    name:  export.name.clone(),
                    extra: Some(SymbolExtra::MachO { flags }),
                }
            })
            .collect();

        Ok(Binary {
            name: macho.name.map(str::to_string),
            kind: BinaryKind::MachO,
            symbols,
            extra: None,
        })
    }

    fn from_mach_archive(mach: &goblin::mach::Mach) -> Result<Vec<Self>> {
        use goblin::mach::Mach;

        match mach {
            Mach::Binary(macho) => {
                let bin = Binary::from_mach_binary(macho)?;
                Ok(vec![bin])
            },
            Mach::Fat(multiarch) => {
                let mut bins: Vec<Binary> = vec![];

                for macho in multiarch.into_iter() {
                    let bin = Binary::from_mach_binary(&macho?)?;
                    bins.push(bin);
                }

                Ok(bins)
            },
        }
    }
}

fn main() {
    let mut bins = vec![];

    for filename in std::env::args().skip(1) {
        let bin = match Binary::from_path(&filename) {
            Ok(bin) => bin,
            Err(err) => {
                eprintln!("Failed to load symbols from \"{}\": {:?}", filename, err);
                continue;
            },
        };

        println!(
            "Found {} symbols in {}",
            bin.symbols.len(),
            bin.name.as_deref().unwrap_or_default()
        );

        bins.push(bin);
    }

    for bin in bins {
        println!("{}:", bin.name.unwrap_or_default());

        for sym in bin.symbols {
            print!("    {:<50}", sym.name());

            if let Some(extra) = sym.extra() {
                print!("{:?}", extra);
            }

            println!();
        }
        println!();
    }
}

pub(crate) mod kiapi {
    #[allow(dead_code)]
    pub mod common {
        include!("generated/kiapi.common.rs");

        pub mod commands {
            include!("generated/kiapi.common.commands.rs");
        }

        pub mod project {
            include!("generated/kiapi.common.project.rs");
        }

        pub mod types {
            include!("generated/kiapi.common.types.rs");
        }
    }

    #[allow(dead_code)]
    pub mod board {
        include!("generated/kiapi.board.rs");

        pub mod commands {
            include!("generated/kiapi.board.commands.rs");
        }

        pub mod types {
            include!("generated/kiapi.board.types.rs");
        }
    }

    #[allow(dead_code)]
    pub mod schematic {
        pub mod types {
            include!("generated/kiapi.schematic.types.rs");
        }
    }
}

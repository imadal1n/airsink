{
  description = "airsink - AirPlay 2 audio streaming for Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      overlays = [ (import rust-overlay) ];
      pkgs = import nixpkgs { inherit system overlays; };

      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        extensions = [ "rust-src" "rust-analyzer" "clippy" ];
      };
    in
    {
      packages.${system}.default = pkgs.rustPlatform.buildRustPackage rec {
        pname = "airsink";
        version = "0.1.0";

        src = builtins.path {
          path = ./.;
          name = "airsink-source";
        };

        cargoLock.lockFile = ./Cargo.lock;

        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
          clang
          makeWrapper
        ];

        buildInputs = with pkgs; [
          # pipewire (native audio capture + virtual sink)
          pipewire

          # pulseaudio utils (pactl for sink routing)
          pulseaudio

          # avahi / mdns (device discovery)
          avahi

          # crypto libs
          openssl

          # dbus (avahi bindings, pipewire comms)
          dbus
        ];

        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

        postFixup = ''
          wrapProgram $out/bin/airsink \
            --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.pulseaudio pkgs.pipewire ]}
        '';

        meta = with pkgs.lib; {
          description = "AirPlay 2 audio streaming for Linux";
          license = licenses.mit;
          platforms = [ "x86_64-linux" ];
        };
      };

      checks.${system} = {
        default = self.packages.${system}.default;
      };

      devShells.${system}.default = pkgs.mkShell {
        name = "airsink";

        nativeBuildInputs = with pkgs; [
          # rust toolchain
          rustToolchain
          pkg-config
          clang
          mold
        ];

        buildInputs = with pkgs; [
          # pipewire (native audio capture + virtual sink)
          pipewire

          # pulseaudio utils (pactl for sink routing)
          pulseaudio

          # avahi / mdns (device discovery)
          avahi

          # crypto libs
          openssl

          # dbus (avahi bindings, pipewire comms)
          dbus
        ];

        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

        # link faster with mold
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = "clang";
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-fuse-ld=mold";

        shellHook = ''
          echo "airsink dev shell"
          echo "rust: $(rustc --version)"
        '';
      };
    };
}

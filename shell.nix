let
  pkgs = import <nixpkgs> {};
in
  pkgs.mkShell {
    packages = [
      pkgs.cargo
      pkgs.rustc
      pkgs.rust-analyzer
      pkgs.rustfmt
      pkgs.darwin.apple_sdk.frameworks.Cocoa
      pkgs.libiconv
    ];
  }

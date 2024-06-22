{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/haskell-updates";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    haskell-flake.url = "github:srid/haskell-flake";
    flake-root.url = "github:srid/flake-root";
  };
  outputs = inputs@{ self, nixpkgs, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = nixpkgs.lib.systems.flakeExposed;
      imports = [
        inputs.haskell-flake.flakeModule
        inputs.flake-root.flakeModule
      ];

      perSystem = { self', pkgs, ... }: {
        haskellProjects.default = {
          basePackages = pkgs.haskell.packages.ghc98;
          settings = {
            tls.check = true;
          };
          devShell.enable = false;
        };

        # haskell-flake doesn't set the default package, but you can do it here.
        packages.default = self'.packages.tls;
      };
    };
}

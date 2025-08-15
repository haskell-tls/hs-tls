{
  description = "A flake for unimatrix";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
  let
    forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
  in
  {
    devShells = forAllSystems (system:
    let
      pkgs = import nixpkgs { inherit system; };
    in
    {
      default = pkgs.mkShell {
        inputsFrom = [];
        packages = with pkgs; [
          ghc
          zlib
          haskellPackages.cabal-install
          haskellPackages.haskell-language-server
          haskellPackages.eventlog2html
        ];
      };
    });
  };
}

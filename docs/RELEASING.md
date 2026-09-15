# Releasing

This repository is its own Homebrew tap — the formula in `Formula/svxconnect.rb`
is what `brew tap guru-rf/svxconnect https://github.com/Guru-RF/SVXConnect-CLI`
pulls. There is no second repository to keep in sync.

Until a version is tagged, the only working Homebrew path is
`brew install --HEAD svxconnect`, which builds from `main`. To publish a stable
release:

1. **Tag it.**

   ```sh
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```

   GitHub then serves the tarball at
   `https://github.com/Guru-RF/SVXConnect-CLI/archive/refs/tags/v0.1.0.tar.gz`.

2. **Get its checksum.**

   ```sh
   curl -sL https://github.com/Guru-RF/SVXConnect-CLI/archive/refs/tags/v0.1.0.tar.gz \
     | shasum -a 256
   ```

3. **Point the formula at it.** In `Formula/svxconnect.rb`, set `url` to the
   tag tarball and replace the placeholder `sha256` with the value from step 2.
   Bump both when you cut a new version.

4. **Check and commit.**

   ```sh
   brew tap guru-rf/svxconnect https://github.com/Guru-RF/SVXConnect-CLI
   brew audit --strict --online guru-rf/svxconnect/svxconnect
   brew install guru-rf/svxconnect/svxconnect        # stable, not --HEAD
   git commit -am "Formula: v0.1.0" && git push
   ```

After that, `brew install svxconnect` (no `--HEAD`) installs the tagged build.

## Arch Linux packages

The PKGBUILDs live in `packaging/arch/`. After tagging:

1. In `packaging/arch/svxconnect/PKGBUILD`, set `pkgver` (and reset `pkgrel=1`)
   and put the tag tarball's checksum from step 2 above in `sha256sums`.
2. Build and test it: `cd packaging/arch/svxconnect && makepkg -f`. `check()`
   runs `make test`.
3. Attach the package, not the `-debug` one, to the GitHub release:

   ```sh
   gh release create v0.1.1 --title v0.1.1 --notes-file NOTES.md \
     packaging/arch/svxconnect/svxconnect-0.1.1-1-x86_64.pkg.tar.zst
   ```

4. In `packaging/arch/svxconnect-bin/PKGBUILD`, set `pkgver` and put
   `sha256sum` of that package file in `sha256sums`.
5. Regenerate each `.SRCINFO`: `makepkg --printsrcinfo > .SRCINFO` in all three
   directories.
6. Update the `pacman -U` URL in `README.md`.

To publish on the AUR, each package directory is its own AUR git repository:

```sh
git clone ssh://aur@aur.archlinux.org/svxconnect.git aur-svxconnect
cp packaging/arch/svxconnect/{PKGBUILD,.SRCINFO} aur-svxconnect/
cd aur-svxconnect && git add PKGBUILD .SRCINFO && git commit -m "0.1.1-1" && git push
```

## Making the repo public

The tap only works for people who can clone the repo, so `brew install --HEAD`
from a stranger needs the repo to be public. Flip it public once you are happy;
nothing in the tap mechanics changes.

## Version bump checklist

- `SVX_VERSION` in `src/main.c`
- `CFBundleShortVersionString` / `CFBundleVersion` in `packaging/macos/Info.plist`
- `url` + `sha256` in `Formula/svxconnect.rb`
- the roadmap/status in `README.md` if anything shifted

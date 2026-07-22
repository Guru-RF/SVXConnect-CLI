class Svxconnect < Formula
  desc "Terminal client for SvxLink reflectors"
  homepage "https://github.com/Guru-RF/SVXConnect-CLI"
  # Stable url + sha256 are placeholders until the first tag; `brew install
  # --HEAD svxconnect` builds from main and needs neither. See docs/RELEASING.md.
  url "https://github.com/Guru-RF/SVXConnect-CLI/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "replace-with-sha256-of-the-release-tarball"
  license "MIT"
  head "https://github.com/Guru-RF/SVXConnect-CLI.git", branch: "main"

  depends_on "pkg-config" => :build
  depends_on "openssl@3"
  depends_on "opus"

  # macOS ships ncurses 6.0 with the wide-character API, use_default_colors()
  # and resize_term(), which is everything this interface needs. Homebrew's
  # ncurses is keg-only and would buy nothing but extra -I/-L juggling.
  uses_from_macos "ncurses"

  # No audio dependency on purpose: the device layer is miniaudio, vendored as
  # a single header, talking to CoreAudio here and dlopen()ing libasound /
  # libpulse at runtime on Linux.

  def install
    # OPENSSL_PREFIX is passed explicitly so the Makefile never shells out to
    # `brew` inside the build sandbox, where it is not available.
    system "make", "install",
           "PREFIX=#{prefix}",
           "OPENSSL_PREFIX=#{formula_opt_prefix("openssl@3")}"
    pkgshare.install "example.conf"
    doc.install "README.md", "docs/PTT.md", "docs/TCC.md"
  end

  def caveats
    <<~EOS
      Get started:
        mkdir -p ~/.config/svxconnect
        cp #{opt_pkgshare}/example.conf ~/.config/svxconnect/svxconnect.conf
        $EDITOR ~/.config/svxconnect/svxconnect.conf
        svxconnect --enroll     # then wait for the reflector sysop to sign
        svxconnect

      Microphone: macOS attributes the request to your TERMINAL application,
      not to svxconnect, so the prompt will name Terminal / iTerm / Ghostty.
      That is normal. If you ever denied it, enable your terminal under
      System Settings > Privacy & Security > Microphone.

      Microphone capture does not work over SSH — use `svxconnect --no-tx`
      there for a receive-only session.

      Transmit is a toggle: SPACE starts, SPACE stops, ESC always stops.
      A terminal cannot see a key being released; see #{opt_doc}/PTT.md.
    EOS
  end

  test do
    assert_match "svxconnect", shell_output("#{bin}/svxconnect --version")

    # --list-devices must work with no configuration at all: it is the first
    # thing anyone runs when the audio is not behaving.
    assert_match "backend", shell_output("#{bin}/svxconnect --list-devices 2>&1")

    # A config with no callsign must be rejected rather than half-started.
    (testpath/"bad.conf").write "reflector = example.org\n"
    output = shell_output("#{bin}/svxconnect -c #{testpath}/bad.conf --headless 2>&1", 1)
    assert_match "callsign", output
  end
end

# Homebrew formula for the `mcpip` CLI (the command you RUN) — a Python
# virtualenv formula that installs the `mcpip-sdk` distribution so the `mcpip`
# binary lands on PATH, exactly like gh / kubectl / vault / stripe on macOS.
#
# Two install paths:
#
#   * TODAY, no published release required:
#       brew install --HEAD mcpip/tap/mcpip
#     builds straight from the git repo (the `head` stanza below); the package
#     lives under sdk/python in the monorepo, so `install` cd's there.
#
#   * AT/AFTER A TAGGED RELEASE:
#       brew tap mcpip/tap && brew install mcpip
#     builds from the published `mcpip-sdk` sdist named by `url` + `sha256`.
#
# The ONLY runtime dependency the mcpip-sdk distribution declares is httpx; the
# remaining `resource` blocks are httpx's own transitive runtime deps, generated
# the way `brew update-python-resources` would (real PyPI sdists + real sha256).
class Mcpip < Formula
  include Language::Python::Virtualenv

  desc "CLI for the MCPIP zero-trust authorization gateway — authorize every AI action"
  homepage "https://github.com/mcpip-security/mcpip"
  license "Apache-2.0"

  # ---------------------------------------------------------------------------
  # STABLE RELEASE STANZA — RELEASE-CEREMONY FILL-IN.
  #
  # The `sha256` below is a DOCUMENTED PLACEHOLDER, never a fabricated digest.
  # `mcpip-sdk` is not yet published to PyPI; until it is, install with
  # `brew install --HEAD mcpip/tap/mcpip`. At tag time the release step
  # (RELEASE.md §"Homebrew stable stanza") publishes the sdist, runs
  # `brew fetch` / `shasum -a 256` on the REAL tarball, and pastes the true
  # 64-hex digest here alongside the matching version.
  # ---------------------------------------------------------------------------
  url "https://files.pythonhosted.org/packages/source/m/mcpip-sdk/mcpip_sdk-0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000" # RELEASE-FILL-IN: real digest, computed from the published tarball at tag time
  version "0.1.0"

  # Bleeding edge, works TODAY without any published release.
  head "https://github.com/mcpip-security/mcpip.git", branch: "main"

  depends_on "python@3.12"

  resource "httpx" do
    url "https://files.pythonhosted.org/packages/b1/df/48c586a5fe32a0f01324ee087459e112ebb7224f646c0b5023f5e79e9956/httpx-0.28.1.tar.gz"
    sha256 "75e98c5f16b0f35b567856f597f06ff2270a374470a5c2392242528e3e3e42fc"
  end

  resource "httpcore" do
    url "https://files.pythonhosted.org/packages/06/94/82699a10bca87a5556c9c59b5963f2d039dbd239f25bc2a63907a05a14cb/httpcore-1.0.9.tar.gz"
    sha256 "6e34463af53fd2ab5d807f399a9b45ea31c3dfa2276f15a2c3f00afff6e176e8"
  end

  resource "h11" do
    url "https://files.pythonhosted.org/packages/01/ee/02a2c011bdab74c6fb3c75474d40b3052059d95df7e73351460c8588d963/h11-0.16.0.tar.gz"
    sha256 "4e35b956cf45792e4caa5885e69fba00bdbc6ffafbfa020300e549b208ee5ff1"
  end

  resource "anyio" do
    url "https://files.pythonhosted.org/packages/61/cc/a381afa6efea9f496eff839d4a6a1aed3bfafc7b3ab4b0d1b243a12573dd/anyio-4.14.2.tar.gz"
    sha256 "cfa139f3ed1a23ee8f88a145ddb5ac7605b8bbfd8592baacd7ce3d8bb4313c7f"
  end

  resource "sniffio" do
    url "https://files.pythonhosted.org/packages/a2/87/a6771e1546d97e7e041b6ae58d80074f81b7d5121207425c964ddf5cfdbd/sniffio-1.3.1.tar.gz"
    sha256 "f4324edc670a0f49750a81b895f35c3adb843cca46f0530f79fc1babb23789dc"
  end

  resource "idna" do
    url "https://files.pythonhosted.org/packages/cd/63/9496c57188a2ee585e0f1db071d75089a11e98aa86eb99d9d7618fc1edce/idna-3.18.tar.gz"
    sha256 "ffb385a7e039654cef1ab9ef32c6fafe283c0c0467bba1d9029738ce4a14a848"
  end

  resource "certifi" do
    url "https://files.pythonhosted.org/packages/c9/c7/424b75da314c1045981bd9777432fad05a9e0c69daa4ed7e308bbaffe405/certifi-2026.6.17.tar.gz"
    sha256 "024c88eeec92ca068db80f02b8b07c9cef7b9fe261d1d535abfd5abd6f6af432"
  end

  # anyio pulls in typing_extensions on Python < 3.13 (this formula targets 3.12).
  resource "typing-extensions" do
    url "https://files.pythonhosted.org/packages/f6/cc/6253133b5bb138fc3306cebfbda2c520f545d36b5be2c7255cc528bb45d6/typing_extensions-4.16.0.tar.gz"
    sha256 "dc983d19a509c94dba722ee6abd33940f7c05a89e243c47e907eb4db6f1a43e5"
  end

  def install
    # The stable sdist IS the mcpip-sdk package (pyproject at its root); a --HEAD
    # checkout is the full monorepo, where the package lives under sdk/python.
    pkg_root = build.head? ? buildpath/"sdk/python" : buildpath

    venv = virtualenv_create(libexec, "python3.12")
    venv.pip_install resources
    venv.pip_install pkg_root
    bin.install_symlink libexec/"bin/mcpip"
  end

  test do
    # `version --client` is a pure-local read (no gateway call) — it prints the
    # installed CLI + SDK version and exits 0, proving the binary is on PATH.
    assert_match "mcpip", shell_output("#{bin}/mcpip version --client")
    # `--help` groups the command tree (gh/kubectl-style) and exits 0.
    assert_match "authorize", shell_output("#{bin}/mcpip --help")
  end
end

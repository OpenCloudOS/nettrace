pkgname=nettrace
pkgver=1.2.11
pkgrel=1
pkgdesc="A skb (network packet) trace tool for kernel"
arch=('x86_64')
url="https://github.com/OpenCloudOS/nettrace"
license=('MulanPSL-2.0')

depends=('libbpf' 'libelf' 'zlib' 'zstd')
makedepends=(
  'binutils'
  'clang'
  'gcc'
  'llvm'
  'make'
  'pkgconf'
  'python'
  'python-yaml'
)
optdepends=(
  'bash-completion: bash completion support'
  'linux-headers: required for NO_BTF/compat builds'
  'bpftool: required for skel builds'
)

source=()
sha256sums=()

_filter_cflags() {
  local _out=()
  local _flag
  for _flag in $CFLAGS; do
    case "${_flag}" in
      -static) ;;
      -march=*|-mtune=*) ;;
      -fcf-protection|-fcf-protection=*) ;;
      -fstack-clash-protection) ;;
      *) _out+=("${_flag}") ;;
    esac
  done
  printf '%s\n' "${_out[*]}"
}

build() {
  cd "${startdir}"
  local _cflags
  _cflags="$(_filter_cflags)"
  CFLAGS="${_cflags}" make VERSION="${pkgver}" RELEASE="${pkgrel}" all
}

package() {
  cd "${startdir}"
  local _cflags
  _cflags="$(_filter_cflags)"
  CFLAGS="${_cflags}" make PREFIX="${pkgdir}" VERSION="${pkgver}" RELEASE="${pkgrel}" install
  install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
}

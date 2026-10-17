'use strict'

// Pre-commit hook for TriPSs/conventional-changelog-action.
// It runs after Cargo.toml has been bumped but before the release commit is
// created, so every other place that carries the release version can be
// synced and shipped within the very same commit.
//
// Props: { tag: string, version: string }

const fs = require('fs')
const path = require('path')

const root = process.cwd()

function read(file) {
  return fs.readFileSync(path.join(root, file), 'utf8')
}

function write(file, content) {
  fs.writeFileSync(path.join(root, file), content)
}

function replaceOnce(content, pattern, replacement, file) {
  if (!pattern.test(content)) {
    throw new Error(`Unable to find the version entry in ${file}`)
  }
  return content.replace(pattern, replacement)
}

exports.preCommit = async (props) => {
  const version = props.version

  const cargoToml = read('Cargo.toml')
  const manifestMatch = cargoToml.match(/^version = "([^"]+)"$/m)
  if (!manifestMatch || manifestMatch[1] !== version) {
    throw new Error(
      `Cargo.toml reports version "${manifestMatch && manifestMatch[1]}", expected "${version}"`
    )
  }

  const cargoLock = replaceOnce(
    read('Cargo.lock'),
    /(name = "hbbs"\nversion = ")([^"]+)(")/,
    `$1${version}$3`,
    'Cargo.lock'
  )
  write('Cargo.lock', cargoLock)

  const setupNsi = replaceOnce(
    read('ui/setup.nsi'),
    /(!define VERSION ")([^"]+)(")/,
    `$1${version}$3`,
    'ui/setup.nsi'
  )
  write('ui/setup.nsi', setupNsi)

  const date = new Date().toUTCString().replace('GMT', '+0000')
  const changelogEntry =
    `rustdesk-server (${version}) UNRELEASED; urgency=medium\n` +
    `\n` +
    `  * Upstream release ${version}\n` +
    `\n` +
    ` -- RustDesk release workflow <noreply@rustdesk.com>  ${date}\n\n`
  write('debian/changelog', changelogEntry + read('debian/changelog'))
}

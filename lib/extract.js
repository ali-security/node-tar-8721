// give it a tarball and a path, and it'll dump the contents

module.exports = Extract

var tar = require("../tar.js")
  , fstream = require("fstream")
  , inherits = require("inherits")
  , path = require("path")
  , fs = require("fs")
  , stripAbsolutePath = require("./strip-absolute-path.js")

var DEFAULT_MAX_DEPTH = 1024

// Check that no symlinks exist in the path hierarchy
// Prevents extraction through symlinks (CVE-2026-26960)
function ensureNoSymlink (cwd, parts) {
  var t = cwd
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i]
    if (!p || p === '.') continue
    t = path.resolve(t, p)
    try {
      var st = fs.lstatSync(t)
      if (st.isSymbolicLink()) {
        return false
      }
    } catch (er) {
      // Path doesn't exist yet, which is fine
    }
  }
  return true
}

function Extract (opts) {
  if (!(this instanceof Extract)) return new Extract(opts)
  tar.Parse.apply(this)

  if (typeof opts !== "object") {
    opts = { path: opts }
  }

  // better to drop in cwd? seems more standard.
  opts.path = opts.path || path.resolve("node-tar-extract")
  opts.type = "Directory"
  opts.Directory = true

  // similar to --strip or --strip-components
  opts.strip = +opts.strip
  if (!opts.strip || opts.strip <= 0) opts.strip = 0

  // prevent excessively deep nesting of subfolders
  // set to `Infinity` to remove this restriction
  this.maxDepth = typeof opts.maxDepth === 'number'
    ? opts.maxDepth
    : DEFAULT_MAX_DEPTH

  this._fst = fstream.Writer(opts)

  this.pause()
  var me = this

  // CVE-2018-20834 fix: Intercept fstream.Writer's "entry" listener
  // Remove hardlinks synchronously AFTER path normalization but BEFORE fstream processes
  // We intercept by wrapping fstream's entry event handling
  var fstEntryListeners = this._fst.listeners("entry")
  // Remove all existing entry listeners from fstream
  this._fst.removeAllListeners("entry")
  // Add our interceptor, then re-add fstream's original listeners
  var meFst = this._fst
  this._fst.on("entry", function (entry) {
    // This runs AFTER the entry handler has normalized the path
    if (entry && entry.type === "File") {
      // Remove hardlink synchronously before fstream processes this entry
      try {
        var fullPath = path.resolve(opts.path, entry.path)
        var stats = fs.lstatSync(fullPath)
        if (stats.nlink > 1) {
          fs.unlinkSync(fullPath)
        }
      } catch (err) {
        // File doesn't exist or other error - that's fine, continue
        if (err.code !== 'ENOENT' && entry.warn) {
          entry.warn('CVE-2018-20834: Could not check/remove hardlink', {
            path: entry.path,
            error: err.message
          })
        }
      }
    }
    // Call fstream's original entry listeners
    for (var i = 0; i < fstEntryListeners.length; i++) {
      fstEntryListeners[i].call(meFst, entry)
    }
  })

  // Hardlinks in tarballs are relative to the root
  // of the tarball.  So, they need to be resolved against
  // the target directory in order to be created properly.
  me.on("entry", function (entry) {
    // if there's a "strip" argument, then strip off that many
    // path components.
    if (opts.strip) {
      var p = entry.path.split("/").slice(opts.strip).join("/")
      entry.path = entry.props.path = p
      if (entry.linkpath) {
        var lp = entry.linkpath.split("/").slice(opts.strip).join("/")
        entry.linkpath = entry.props.linkpath = lp
      }
    }

    // Check for excessively deep paths
    var depthParts = entry.path.split("/")
    if (isFinite(me.maxDepth) && depthParts.length > me.maxDepth) {
      entry.abort()
      if (entry.warn) {
        entry.warn('TAR_ENTRY_ERROR', 'path has ' + depthParts.length +
          ' components, exceeding ' + me.maxDepth, {
          path: entry.path,
          depth: depthParts.length,
          maxDepth: me.maxDepth
        })
      }
      return
    }

    // Normalize path separators for consistent checking
    var p = entry.path.replace(/\\/g, '/')

    // Strip absolute path root BEFORE checking for '..'
    // This ensures that drive-local paths like c:../foo get their root stripped
    // to ../foo, which is then correctly caught by the '..' check below
    var s = stripAbsolutePath(p)
    if (s[0]) {
      entry.path = s[1]
      entry.props.path = s[1]
      p = s[1]
      if (entry.warn) {
        entry.warn('stripping ' + s[0] + ' from absolute path', entry.path)
      }
    }

    // Check for path traversal attempts (after stripping root)
    var parts = p.replace(/\\/g, '/').split('/')
    if (parts.indexOf('..') !== -1) {
      if (entry.warn) {
        entry.warn('TAR_ENTRY_ERROR', 'path contains \'..\'', {
          entry: entry,
          path: p
        })
      }
      return // Skip this entry
    }

    // Resolve the absolute path for this entry using the already-split parts
    // Use parts.join('/') rather than the raw path to avoid drive-relative
    // prefixes like c: confusing path.resolve
    entry.absolute = path.resolve(opts.path, parts.join('/'))

    // Defense in depth: ensure the resolved path doesn't escape the extraction directory
    // This should have been prevented above, but provides additional safety
    var extractPath = path.resolve(opts.path)
    var normalizedExtract = extractPath.replace(/\\/g, '/')
    var normalizedEntry = entry.absolute.replace(/\\/g, '/')

    if (normalizedEntry.indexOf(normalizedExtract + '/') !== 0 &&
      normalizedEntry !== normalizedExtract) {
      if (entry.warn) {
        entry.warn('TAR_ENTRY_ERROR', 'path escaped extraction target', {
          entry: entry,
          path: p,
          resolvedPath: normalizedEntry,
          cwd: normalizedExtract
        })
      }
      return // Skip this entry
    }

    // Sanitize linkpath the same way as path: strip absolute roots and reject '..'
    if (entry.linkpath) {
      var lp = entry.linkpath.replace(/\\/g, '/')
      var ls = stripAbsolutePath(lp)
      if (ls[0]) {
        lp = ls[1]
        entry.linkpath = ls[1]
        entry.props.linkpath = ls[1]
        if (entry.warn) {
          entry.warn('stripping ' + ls[0] + ' from absolute linkpath', entry.linkpath)
        }
      }
      var lpParts = lp.replace(/\\/g, '/').split('/')
      // Symlinks can legitimately use relative '..' paths, but hardlinks
      // resolve relative to cwd so '..' is always an escape attempt
      if (lpParts.indexOf('..') !== -1 && entry.type === 'Link') {
        if (entry.warn) {
          entry.warn('TAR_ENTRY_ERROR', 'linkpath contains \'..\'', {
            entry: entry,
            path: lp
          })
        }
        return // Skip this entry
      }
    }

    // CVE-2026-26960: Ensure no intermediate path component is a symlink
    // before extracting. fstream follows symlinks, so an attacker could place
    // a symlink entry pointing outside the extraction dir and then place a file
    // entry that traverses through it.
    var entryDir = path.resolve(opts.path, path.dirname(entry.path))
    var relDir = path.relative(opts.path, entryDir)
    if (relDir && relDir !== '.') {
      var dirParts = relDir.split(path.sep)
      if (!ensureNoSymlink(opts.path, dirParts)) {
        if (entry.warn) {
          entry.warn('TAR_SYMLINK_ERROR', 'cannot extract through symbolic link', {
            entry: entry,
            path: entry.path,
            into: entryDir
          })
        }
        return
      }
    }

    if (entry.type === "Link") {
      entry.linkpath = entry.props.linkpath =
        path.join(opts.path, path.join("/", entry.props.linkpath))

      // Also check symlink components in the resolved hardlink target
      var linkTarget = path.resolve(entry.linkpath)
      var relLink = path.relative(opts.path, linkTarget)
      if (relLink) {
        var linkDirParts = relLink.split(path.sep)
        if (!ensureNoSymlink(opts.path, linkDirParts)) {
          if (entry.warn) {
            entry.warn('TAR_SYMLINK_ERROR', 'cannot extract through symbolic link', {
              entry: entry,
              path: entry.path,
              into: linkTarget
            })
          }
          return
        }
      }
    }

    if (entry.type === "SymbolicLink") {
      var dn = path.dirname(entry.path) || ""
      var linkpath = entry.props.linkpath
      var target = path.resolve(opts.path, dn, linkpath)
      if (target.indexOf(opts.path) !== 0) {
        linkpath = path.join(opts.path, path.join("/", linkpath))
      }
      entry.linkpath = entry.props.linkpath = linkpath
    }

  })

  this._fst.on("ready", function () {
    me.pipe(me._fst, { end: false })
    me.resume()
  })

  this._fst.on('error', function(err) {
    me.emit('error', err)
  })

  this._fst.on('drain', function() {
    me.emit('drain')
  })

  // this._fst.on("end", function () {
  //   console.error("\nEEEE Extract End", me._fst.path)
  // })

  this._fst.on("close", function () {
    // console.error("\nEEEE Extract End", me._fst.path)
    me.emit("finish")
    me.emit("end")
    me.emit("close")
  })
}

inherits(Extract, tar.Parse)

Extract.prototype._streamEnd = function () {
  var me = this
  if (!me._ended || me._entry) me.error("unexpected eof")
  me._fst.end()
  // my .end() is coming later.
}

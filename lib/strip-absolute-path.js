// unix absolute paths are also absolute on win32, so we use this for both

// manually extract root from path (for Node 0.10 compatibility - path.parse doesn't exist)
// Returns the root portion of the path
function getRoot(p) {
    // Windows path with forward slashes: //foo/bar/...
    // Test case shows: //foo//bar//baz -> root is // (not //foo/bar/)
    // So we treat // as just a root of //
    // But handle //?/C:/ paths specially - they should return //?/C:/
    // This must be checked BEFORE the simple '/' check
    if (p.charAt(0) === '/' && p.charAt(1) === '/') {
        // Check for //?/X:/ pattern (extended-length path)
        // Pattern: //?/X:/ where X is a drive letter
        if (p.length >= 4 && p.charAt(2) === '?' && p.charAt(3) === '/') {
            // Check if we have at least 6 characters and a drive letter pattern
            if (p.length >= 6) {
                var driveLetter = p.charAt(4)
                var colon = p.charAt(5)
                // Verify drive letter is A-Z or a-z and colon is present
                if (driveLetter && colon === ':') {
                    var code = driveLetter.charCodeAt(0)
                    if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
                        // Check if there's a trailing slash (//?/X:/ pattern)
                        if (p.length >= 7 && p.charAt(6) === '/') {
                            return p.substr(0, 7) // //?/X:/
                        }
                        // No trailing slash (//?/X: pattern)
                        return p.substr(0, 6) // //?/X:
                    }
                }
            }
        }
        return '//'
    }

    // Unix absolute path
    if (p.charAt(0) === '/') {
        return '/'
    }

    // Windows UNC path with backslashes: \\server\share\...
    // Pattern: \\foo\bar\baz -> root is \\foo\bar\
    // Also handle \\?\X:\ paths (extended-length path with backslashes)
    if (p.charAt(0) === '\\' && p.charAt(1) === '\\') {
        // Check for \\?\X:\ pattern (extended-length path)
        if (p.length >= 6 && p.charAt(2) === '?' && p.charAt(3) === '\\' &&
            /^[a-zA-Z]:/.test(p.substr(4))) {
            // Find the drive letter, colon, and backslash
            var idx = 6
            if (p.charAt(6) === '\\') {
                return p.substr(0, 7) // \\?\X:\
            }
            return p.substr(0, 6) // \\?\X:
        }
        // Find server name (after \\)
        var idx = 2
        while (idx < p.length && p.charAt(idx) !== '\\' && p.charAt(idx) !== '/') {
            idx++
        }
        if (idx < p.length) {
            idx++ // include the separator
            // Find share name
            while (idx < p.length && p.charAt(idx) !== '\\' && p.charAt(idx) !== '/') {
                idx++
            }
            if (idx < p.length) {
                idx++ // include the separator
                return p.substr(0, idx)
            }
            // If no share separator found, return up to server
            return p.substr(0, idx)
        }
        return p.substr(0, 2) // just \\
    }

    // Windows drive letter: C:\ or C:/ or C:///
    // Test case: c:///a/b/c -> root is c:///
    // Also handle drive-local paths like c:../foo (root is c:)
    if (p.length >= 2 && /^[a-zA-Z]:/.test(p)) {
        // Check if it's followed by \ or /
        if (p.charAt(2) === '\\' || p.charAt(2) === '/') {
            // Count consecutive slashes/backslashes
            var idx = 3
            var sep = p.charAt(2)
            while (idx < p.length && (p.charAt(idx) === '\\' || p.charAt(idx) === '/')) {
                idx++
            }
            return p.substr(0, idx)
        } else {
            // Drive-local path (e.g., c:../foo) - return just the drive letter and colon
            return p.substr(0, 2)
        }
    }

    // No root found
    return ''
}

// manually check if path is absolute (for Node 0.10 compatibility)
// Unix absolute: starts with '/'
// Windows absolute: has a drive letter or UNC path
// Note: unix absolute paths are also absolute on win32
function isAbsolute(p) {
    if (p.charAt(0) === '/') return true
    if (p.charAt(0) === '\\' && p.charAt(1) === '\\') return true
    if (/^[a-zA-Z]:[\\\/]/.test(p)) return true
    return false
}

// returns [root, stripped]
// Note that windows will think that //x/y/z/a has a "root" of //x/y, and in
// those cases, we want to sanitize it to x/y/z/a, not z/a, so we strip /
// explicitly if it's the first character.
// drive-specific relative paths on Windows get their root stripped off even
// though they are not absolute, so `c:../foo` becomes ['c:', '../foo']
module.exports = function (p) {
    var r = ''
    // Check for drive-local paths (e.g., c:../foo) which have a root but aren't absolute
    var root = getRoot(p)
    while (isAbsolute(p) || root) {
        // windows will think that //x/y/z has a "root" of //x/y/
        // but strip the //?/C:/ off of //?/C:/path
        if (p.charAt(0) === '/' && p.substr(0, 4) !== '//?/') {
            root = '/'
        } else {
            root = getRoot(p)
        }
        if (!root) break
        p = p.substr(root.length)
        r += root
        root = getRoot(p)
    }
    return [r, p]
}


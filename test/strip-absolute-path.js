var tap = require('tap')
var stripAbsolutePath = require('../lib/strip-absolute-path.js')

tap.test('basic', function (t) {
    var cases = {
        '/': ['/', ''],
        '////': ['////', ''],
        'c:///a/b/c': ['c:///', 'a/b/c'],
        '\\\\foo\\bar\\baz': ['\\\\foo\\bar\\', 'baz'],
        '//foo//bar//baz': ['//', 'foo//bar//baz'],
        'c:\\c:\\c:\\c:\\\\d:\\e/f/g': ['c:\\c:\\c:\\c:\\\\d:\\', 'e/f/g'],
    }

    var keys = Object.keys(cases)
    for (var i = 0; i < keys.length; i++) {
        var input = keys[i]
        var expected = cases[input]
        var root = expected[0]
        var stripped = expected[1]
        var result = stripAbsolutePath(input)
        if (!t.equivalent(result, [root, stripped], input)) {
            break
        }
    }
    t.end()
})

tap.test('drive-local paths', function (t) {
    // These test cases are particularly important for Windows path handling
    // Drive-local paths like c:../foo have a root (c:) even though they're not absolute
    var cases = {
        'c:..\\system\\explorer.exe': ['c:', '..\\system\\explorer.exe'],
        'd:..\\..\\unsafe\\land': ['d:', '..\\..\\unsafe\\land'],
        'c:foo': ['c:', 'foo'],
        'D:mark': ['D:', 'mark'],
        '//?/X:/y/z': ['//?/X:/', 'y/z'],
        '\\\\?\\X:\\y\\z': ['\\\\?\\X:\\', 'y\\z'],
    }

    var keys = Object.keys(cases)
    for (var i = 0; i < keys.length; i++) {
        var input = keys[i]
        var expected = cases[input]
        var root = expected[0]
        var stripped = expected[1]
        var result = stripAbsolutePath(input)
        if (!t.equivalent(result, [root, stripped], input)) {
            break
        }
    }
    t.end()
})


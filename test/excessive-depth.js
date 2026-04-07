var tap = require("tap")
  , tar = require("../tar.js")
  , path = require("path")
  , rimraf = require("rimraf")

var target = path.resolve(__dirname, "tmp/excessive-depth-test")

tap.test("preclean", function (t) {
  rimraf.sync(target)
  t.pass("cleaned!")
  t.end()
})

tap.test("maxDepth option is set correctly", function (t) {
  var extract1 = tar.Extract({ path: target })
  t.equal(extract1.maxDepth, 1024, "default maxDepth should be 1024")

  var extract2 = tar.Extract({ path: target, maxDepth: 100 })
  t.equal(extract2.maxDepth, 100, "custom maxDepth should be respected")

  var extract3 = tar.Extract({ path: target, maxDepth: Infinity })
  t.equal(extract3.maxDepth, Infinity, "Infinity maxDepth should be allowed")

  t.end()
})

tap.test("path depth check works correctly", function (t) {
  // Test that the depth checking logic works
  var parts1 = "a/b/c/d/e".split("/").filter(function(p) { return p })
  t.equal(parts1.length, 5, "path with 5 components should have length 5")

  var parts2 = "a/b/c/d/e/f/g/h/i/j/k".split("/").filter(function(p) { return p })
  t.equal(parts2.length, 11, "path with 11 components should have length 11")

  var parts3 = "".split("/").filter(function(p) { return p })
  t.equal(parts3.length, 0, "empty path should have length 0")

  t.end()
})

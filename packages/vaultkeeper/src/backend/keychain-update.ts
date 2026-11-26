/**
 * Native Keychain replacement script for the system JXA runner.
 * Keep in sync with crates/vaultkeeper-core/src/backend/keychain-update.js.
 * @internal
 */
export const KEYCHAIN_UPDATE_SCRIPT = `// The macOS JXA bridge provides an update-only Keychain operation without a compiler or bundled binary.
ObjC.import('Foundation');
ObjC.import('Security');
ObjC.bindFunction('SecKeychainOpen', ['int', ['char *', 'void **']]);
ObjC.bindFunction('SecKeychainFindGenericPassword', ['int', ['void *', 'unsigned int', 'char *', 'unsigned int', 'char *', 'void *', 'void *', 'void **']]);
ObjC.bindFunction('SecKeychainItemModifyContent', ['int', ['void *', 'void *', 'unsigned int', 'void *']]);
ObjC.bindFunction('CFRelease', ['void', ['void *']]);
ObjC.bindFunction('fdopen', ['void *', ['int', 'char *']]);
ObjC.bindFunction('setbuf', ['void', ['void *', 'void *']]);
ObjC.bindFunction('fread', ['unsigned long', ['void *', 'unsigned long', 'unsigned long', 'void *']]);
ObjC.bindFunction('fclose', ['int', ['void *']]);

// Only metadata is in argv. Return the full OSStatus or a local input-failure token.
function run(args) {
  var path = args[0];
  var service = args[1];
  var account = args[2];
  var size = Number(args[3]);
  // Even a zero-length update needs a non-null data pointer to clear the password.
  var capacity = Math.max(1, size);
  var data = $.NSMutableData.dataWithLength(capacity);
  try {
    var input = $.fdopen(0, 'rb');
    try {
      // Read the entire replacement before touching Keychain, without a second stdio buffer.
      $.setbuf(input, null);
      if (Number($.fread(data.mutableBytes, 1, size, input)) !== size) return 'incomplete-input';
    } finally {
      $.fclose(input);
    }
    var keychain = Ref();
    var status = $.SecKeychainOpen(path, keychain);
    if (status !== 0) return status;
    try {
      var item = Ref();
      var serviceSize = $(service).lengthOfBytesUsingEncoding($.NSUTF8StringEncoding);
      status = $.SecKeychainFindGenericPassword(keychain[0], serviceSize, service, account.length, account, null, null, item);
      if (status !== 0) return status;
      try {
        // Find only within the owning keychain. Modify the item reference without any add fallback.
        return $.SecKeychainItemModifyContent(item[0], null, size, data.mutableBytes);
      } finally {
        $.CFRelease(item[0]);
      }
    } finally {
      $.CFRelease(keychain[0]);
    }
  } finally {
    data.resetBytesInRange($.NSMakeRange(0, capacity));
  }
}
`

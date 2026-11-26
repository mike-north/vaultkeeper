/**
 * Read-only native Keychain miss confirmation for the system JXA runner.
 * Keep in sync with crates/vaultkeeper-core/src/backend/keychain-confirm-miss.js.
 * @internal
 */
export const KEYCHAIN_CONFIRM_MISS_SCRIPT = `// Confirms an ordinary security(1) miss against each keychain in the effective search list.
ObjC.import('Foundation');
ObjC.import('Security');
ObjC.bindFunction('SecKeychainCopySearchList', ['int', ['void **']]);
ObjC.bindFunction('SecKeychainGetStatus', ['int', ['void *', 'unsigned int *']]);
ObjC.bindFunction('SecKeychainFindGenericPassword', ['int', ['void *', 'unsigned int', 'char *', 'unsigned int', 'char *', 'void *', 'void *', 'void **']]);
ObjC.bindFunction('CFArrayGetCount', ['long', ['void *']]);
ObjC.bindFunction('CFArrayGetValueAtIndex', ['void *', ['void *', 'long']]);
ObjC.bindFunction('CFRelease', ['void', ['void *']]);

// Query the keychain itself: a cursor can swallow an error while opening it.
function readable(keychain) {
  var flags = Ref();
  var status = $.SecKeychainGetStatus(keychain, flags);
  if (status !== 0) return status;
  var kSecReadPermStatus = 2;
  return (flags[0] & kSecReadPermStatus) !== 0 ? 0 : 'unreadable-keychain';
}

// Only account and service metadata cross argv. Only a confirmed absence permits an add.
function run(args) {
  var service = args[0];
  var account = args[1];
  var serviceSize = $(service).lengthOfBytesUsingEncoding($.NSUTF8StringEncoding);
  var errSecItemNotFound = -25300;
  var searchList = Ref();
  var status = $.SecKeychainCopySearchList(searchList);
  if (status !== 0) return status;
  try {
    var count = Number($.CFArrayGetCount(searchList[0]));
    if (count === 0) return 'empty-search-list';
    for (var i = 0; i < count; i++) {
      var keychain = $.CFArrayGetValueAtIndex(searchList[0], i);
      status = readable(keychain);
      if (status !== 0) return status;
      // Scope the metadata query to one keychain so another keychain cannot mask its error.
      status = $.SecKeychainFindGenericPassword(keychain, serviceSize, service, account.length, account, null, null, null);
      if (status === 0) return 'present';
      if (status !== errSecItemNotFound) return status;
      status = readable(keychain);
      if (status !== 0) return status;
    }
    return 'absent';
  } finally {
    $.CFRelease(searchList[0]);
  }
}
`

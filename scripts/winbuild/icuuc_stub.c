/* Build-time stand-in for Windows' system icuuc.dll (Windows 10 1903+), which Wine lacks.
 * Qt6Core.dll imports these converter functions; PyInstaller only needs QtCore to *load* while it
 * analyses the app. scripts/build_windows_wine.sh puts this DLL into the Wine prefix's system32 only;
 * PyInstaller never bundles system32 DLLs, so on a real PC the app uses the real Windows ICU.
 * Every converter "fails" (ucnv_open → U_UNSUPPORTED_ERROR), which Qt treats as "codec unavailable". */
#define EXPORT __declspec(dllexport)
#define U_UNSUPPORTED_ERROR 16

EXPORT void *ucnv_open(const char *name, int *err) { (void)name; if (err) *err = U_UNSUPPORTED_ERROR; return 0; }
EXPORT int ucnv_countAvailable(void) { return 0; }
EXPORT const char *ucnv_getAvailableName(int n) { (void)n; return 0; }
EXPORT const char *ucnv_getStandardName(const char *name, const char *standard, int *err) {
    (void)name; (void)standard; if (err) *err = U_UNSUPPORTED_ERROR; return 0;
}

#define STUB(name) EXPORT long long name(void) { return 0; }
STUB(ucnv_close) STUB(ucnv_reset) STUB(ucnv_getMaxCharSize) STUB(ucnv_getName)
STUB(ucnv_getToUCallBack) STUB(ucnv_getFromUCallBack) STUB(ucnv_setToUCallBack) STUB(ucnv_setFromUCallBack)
STUB(ucnv_cbToUWriteUChars) STUB(ucnv_cbFromUWriteUChars) STUB(ucnv_toUnicode) STUB(ucnv_fromUnicode)
STUB(ucnv_toUCountPending) STUB(ucnv_fromUCountPending)
STUB(UCNV_FROM_U_CALLBACK_SUBSTITUTE) STUB(UCNV_TO_U_CALLBACK_SUBSTITUTE)

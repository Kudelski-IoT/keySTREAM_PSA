// Enable this for logs
// #define ENABLE_SAL_OBJ_DEBUG_PRINTS
#ifdef ENABLE_SAL_OBJ_DEBUG_PRINTS

#define devLog(...)                          ((void)printf(__VA_ARGS__))
#define devLogErr(...)                       ((void)printf(__VA_ARGS__))
#define devLogKStatus(xValue, xpText)  \
  do { \
    devLog("return status: %d \r\n", xValue); \
    devLog("%s " xpText, __func__); \
  } while (0)


#else
#define devLog(...)                   ((void)0)
#define devLogErr(...)                ((void)0)
#define devLogKStatus(...)            ((void)0)
#endif /* ENABLE_SAL_OBJ_DEBUG_PRINTS */

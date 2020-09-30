// dalvik vm/Common.h
/*
 * These match the definitions in the VM specification.
 */
// typedef uint8_t             u1;
// typedef uint16_t            u2;
// typedef uint32_t            u4;
// typedef uint64_t            u8;
// typedef int8_t              s1;
// typedef int16_t             s2;
// typedef int32_t             s4;
// typedef int64_t             s8;

typedef unsigned char       u1;
typedef unsigned short      u2;
typedef unsigned int        u4;

#define kSHA1DigestLen 20
/*
 * Direct-mapped "header_item" struct.
 */
struct DexHeader {
    u1  magic[8];           /* includes version number */
    u4  checksum;           /* adler32 checksum */
    u1  signature[kSHA1DigestLen]; /* SHA-1 hash */
    u4  fileSize;           /* length of entire file */
    u4  headerSize;         /* offset to start of next section */
    u4  endianTag;
    u4  linkSize;
    u4  linkOff;
    u4  mapOff;
    u4  stringIdsSize;
    u4  stringIdsOff;
    u4  typeIdsSize;
    u4  typeIdsOff;
    u4  protoIdsSize;
    u4  protoIdsOff;
    u4  fieldIdsSize;
    u4  fieldIdsOff;
    u4  methodIdsSize;
    u4  methodIdsOff;
    u4  classDefsSize;
    u4  classDefsOff;
    u4  dataSize;
    u4  dataOff;
};

/*
 * Direct-mapped "map_item".
 */
struct DexMapItem {
    u2 type;              /* type code (see kDexType* above) */
    u2 unused;
    u4 size;              /* count of items of the indicated type */
    u4 offset;            /* file offset to the start of data */
};
/*
 * Direct-mapped "map_list".
 */
struct DexMapList {
    u4  size;               /* #of entries in list */
    DexMapItem list[1];     /* entries */
};
/*
 * Direct-mapped "string_id_item".
 */
struct DexStringId {
    u4 stringDataOff;      /* file offset to string_data_item */
};
/*
 * Direct-mapped "type_id_item".
 */
struct DexTypeId {
    u4  descriptorIdx;      /* index into stringIds list for type descriptor */
};
/*
 * Direct-mapped "field_id_item".
 */
struct DexFieldId {
    u2  classIdx;           /* index into typeIds list for defining class */
    u2  typeIdx;            /* index into typeIds for field type */
    u4  nameIdx;            /* index into stringIds for field name */
};
/*
 * Direct-mapped "method_id_item".
 */
struct DexMethodId {
    u2  classIdx;           /* index into typeIds list for defining class */
    u2  protoIdx;           /* index into protoIds for method prototype */
    u4  nameIdx;            /* index into stringIds for method name */
};
/*
 * Direct-mapped "proto_id_item".
 */
struct DexProtoId {
    u4  shortyIdx;          /* index into stringIds for shorty descriptor */
    u4  returnTypeIdx;      /* index into typeIds list for return type */
    u4  parametersOff;      /* file offset to type_list for parameter types */
};
/*
 * Direct-mapped "class_def_item".
 */
struct DexClassDef {
    u4  classIdx;           /* index into typeIds for this class */
    u4  accessFlags;
    u4  superclassIdx;      /* index into typeIds for superclass */
    u4  interfacesOff;      /* file offset to DexTypeList */
    u4  sourceFileIdx;      /* index into stringIds for source file name */
    u4  annotationsOff;     /* file offset to annotations_directory_item */
    u4  classDataOff;       /* file offset to class_data_item */
    u4  staticValuesOff;    /* file offset to DexEncodedArray */
};
/*
 * Direct-mapped "type_item".
 */
struct DexTypeItem {
    u2  typeIdx;            /* index into typeIds */
};
/*
 * Direct-mapped "type_list".
 */
struct DexTypeList {
    u4  size;               /* #of entries in list */
    DexTypeItem list[1];    /* entries */
};
/*
 * Direct-mapped "code_item".
 *
 * The "catches" table is used when throwing an exception,
 * "debugInfo" is used when displaying an exception stack trace or
 * debugging. An offset of zero indicates that there are no entries.
 */
struct DexCode {
    u2  registersSize;
    u2  insSize;
    u2  outsSize;
    u2  triesSize;
    u4  debugInfoOff;       /* file offset to debug info stream */
    u4  insnsSize;          /* size of the insns array, in u2 units */
    u2  insns[1];
    /* followed by optional u2 padding */
    /* followed by try_item[triesSize] */
    /* followed by uleb128 handlersSize */
    /* followed by catch_handler_item[handlersSize] */
};
/*
 * Direct-mapped "try_item".
 */
struct DexTry {
    u4  startAddr;          /* start address, in 16-bit code units */
    u2  insnCount;          /* instruction count, in 16-bit code units */
    u2  handlerOff;         /* offset in encoded handler data to handlers */
};
/*
 * Link table.  Currently undefined.
 */
struct DexLink {
    u1  bleargh;
};
/*
 * Direct-mapped "annotations_directory_item".
 */
struct DexAnnotationsDirectoryItem {
    u4  classAnnotationsOff;  /* offset to DexAnnotationSetItem */
    u4  fieldsSize;           /* count of DexFieldAnnotationsItem */
    u4  methodsSize;          /* count of DexMethodAnnotationsItem */
    u4  parametersSize;       /* count of DexParameterAnnotationsItem */
    /* followed by DexFieldAnnotationsItem[fieldsSize] */
    /* followed by DexMethodAnnotationsItem[methodsSize] */
    /* followed by DexParameterAnnotationsItem[parametersSize] */
};
/*
 * Direct-mapped "field_annotations_item".
 */
struct DexFieldAnnotationsItem {
    u4  fieldIdx;
    u4  annotationsOff;             /* offset to DexAnnotationSetItem */
};
/*
 * Direct-mapped "method_annotations_item".
 */
struct DexMethodAnnotationsItem {
    u4  methodIdx;
    u4  annotationsOff;             /* offset to DexAnnotationSetItem */
};
/*
 * Direct-mapped "parameter_annotations_item".
 */
struct DexParameterAnnotationsItem {
    u4  methodIdx;
    u4  annotationsOff;             /* offset to DexAnotationSetRefList */
};
/*
 * Direct-mapped "annotation_set_ref_item".
 */
struct DexAnnotationSetRefItem {
    u4  annotationsOff;             /* offset to DexAnnotationSetItem */
};
/*
 * Direct-mapped "annotation_set_ref_list".
 */
struct DexAnnotationSetRefList {
    u4  size;
    DexAnnotationSetRefItem list[1];
};
/*
 * Direct-mapped "annotation_set_item".
 */
struct DexAnnotationSetItem {
    u4  size;
    u4  entries[1];                 /* offset to DexAnnotationItem */
};
/*
 * Direct-mapped "annotation_item".
 *
 * NOTE: this structure is byte-aligned.
 */
struct DexAnnotationItem {
    u1  visibility;
    u1  annotation[1];              /* data in encoded_annotation format */
};

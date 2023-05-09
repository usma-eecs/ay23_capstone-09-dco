{
  "description" : "zeek.OS",
  "processors" : [
    { "remove":         { "field": ["host"],        "ignore_failure": true                                              }  },
    { "json":           { "field": "message",       "target_field": "message2",                    "ignore_failure": true   }  },
    { "rename":         { "field": "message2.os",    "target_field" : "detection.OS",              "ignore_failure": true   }  },
    { "rename":         { "field": "message2.ip",    "target_field" : "source.ip",                 "ignore_failure": true   }  },
    { "pipeline":        { "name": "zeek.common"                                                                         }  }
  ]
}

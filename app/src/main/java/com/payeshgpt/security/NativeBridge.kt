package com.payeshgpt.security

/** JNI bridge to the Rust evidence evaluator. */
object NativeBridge {
    init { System.loadLibrary("payesh_core") }
    @JvmStatic external fun assessJson(evidenceJson: String): String
}

package com.payeshgpt.security

/** JNI bridge to the Rust evidence evaluator. */
class NativeBridge {
    external fun assessJson(evidenceJson: String): String

    companion object {
        init { System.loadLibrary("payesh_core") }
    }
}

rule python_bytecode_version__1_5 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 1.5"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x994e0d0a
}

rule python_bytecode_version__1_5_1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 1.5.1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x994e0d0a
}

rule python_bytecode_version__1_5_2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 1.5.2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x994e0d0a
}

rule python_bytecode_version__1_6 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 1.6"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xfcc40d0a
}

rule python_bytecode_version__2_0 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.0"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x87c60d0a
}

rule python_bytecode_version__2_0_1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.0.1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x87c60d0a
}

rule python_bytecode_version__2_1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x2aeb0d0a
}

rule python_bytecode_version__2_1_1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.1.1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x2aeb0d0a
}

rule python_bytecode_version__2_1_2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.1.2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x2aeb0d0a
}

rule python_bytecode_version__2_2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x2ded0d0a
}

rule python_bytecode_version__2_3a0 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.3a0"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x3bf20d0a or 
        uint32be(0) == 0x45f20d0a or 
        uint32be(0) == 0x3bf20d0a
}

rule python_bytecode_version__2_4a0 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.4a0"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x59f20d0a
}

rule python_bytecode_version__2_4a3 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.4a3"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x63f20d0a
}

rule python_bytecode_version__2_4b1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.4b1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x6df20d0a
}

rule python_bytecode_version__2_5a0 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.5a0"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x77f20d0a or 
        uint32be(0) == 0x81f20d0a or 
        uint32be(0) == 0x8bf20d0a or 
        uint32be(0) == 0x8cf20d0a
}

rule python_bytecode_version__2_5b3 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.5b3"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x95f20d0a or 
        uint32be(0) == 0x9ff20d0a
}

rule python_bytecode_version__2_5c1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.5c1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xa9f20d0a
}

rule python_bytecode_version__2_5c2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.5c2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xb3f20d0a
}

rule python_bytecode_version__2_6a0 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.6a0"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xc7f20d0a
}

rule python_bytecode_version__2_6a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.6a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xd1f20d0a
}

rule python_bytecode_version__2_7a0 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 2.7a0"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xdbf20d0a or 
        uint32be(0) == 0xe5f20d0a or 
        uint32be(0) == 0xeff20d0a or 
        uint32be(0) == 0xf9f20d0a or 
        uint32be(0) == 0x03f30d0a
}

rule python_bytecode_version__3000 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3000"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xb80b0d0a or 
        uint32be(0) == 0xc20b0d0a or 
        uint32be(0) == 0xcc0b0d0a or 
        uint32be(0) == 0xd60b0d0a or 
        uint32be(0) == 0xe00b0d0a or 
        uint32be(0) == 0xea0b0d0a or 
        uint32be(0) == 0xf40b0d0a or 
        uint32be(0) == 0xf50b0d0a or 
        uint32be(0) == 0xff0b0d0a or 
        uint32be(0) == 0x090c0d0a or 
        uint32be(0) == 0x130c0d0a or 
        uint32be(0) == 0x1d0c0d0a or 
        uint32be(0) == 0x1f0c0d0a
}

rule python_bytecode_version__3_0a4 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.0a4"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x270c0d0a
}

rule python_bytecode_version__3_0b1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.0b1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x3b0c0d0a
}

rule python_bytecode_version__3_1a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.1a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x450c0d0a or 
        uint32be(0) == 0x4f0c0d0a
}

rule python_bytecode_version__3_2a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.2a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x580c0d0a
}

rule python_bytecode_version__3_2a2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.2a2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x620c0d0a
}

rule python_bytecode_version__3_2a3 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.2a3"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x6c0c0d0a
}

rule python_bytecode_version__3_3a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.3a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x760c0d0a or 
        uint32be(0) == 0x800c0d0a or 
        uint32be(0) == 0x8a0c0d0a
}

rule python_bytecode_version__3_3a2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.3a2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x940c0d0a
}

rule python_bytecode_version__3_3a4 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.3a4"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x9e0c0d0a
}

rule python_bytecode_version__3_4a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.4a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xb20c0d0a or 
        uint32be(0) == 0xbc0c0d0a or 
        uint32be(0) == 0xc60c0d0a or 
        uint32be(0) == 0xd00c0d0a
}

rule python_bytecode_version__3_4a4 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.4a4"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xda0c0d0a or 
        uint32be(0) == 0xe40c0d0a
}

rule python_bytecode_version__3_4rc2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.4rc2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xee0c0d0a
}

rule python_bytecode_version__3_5a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.5a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xf80c0d0a
}

rule python_bytecode_version__3_5b1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.5b1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x020d0d0a
}

rule python_bytecode_version__3_5b2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.5b2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x0c0d0d0a
}

rule python_bytecode_version__3_5b3 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.5b3"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x160d0d0a
}

rule python_bytecode_version__3_5_2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.5.2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x170d0d0a
}

rule python_bytecode_version__3_6a0 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.6a0"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x200d0d0a
}

rule python_bytecode_version__3_6a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.6a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x210d0d0a
}

rule python_bytecode_version__3_6a2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.6a2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x2a0d0d0a or 
        uint32be(0) == 0x2b0d0d0a or 
        uint32be(0) == 0x2c0d0d0a
}

rule python_bytecode_version__3_6b1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.6b1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x2d0d0d0a or 
        uint32be(0) == 0x2f0d0d0a or 
        uint32be(0) == 0x300d0d0a or 
        uint32be(0) == 0x310d0d0a
}

rule python_bytecode_version__3_6b2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.6b2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x320d0d0a
}

rule python_bytecode_version__3_6rc1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.6rc1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x330d0d0a
}

rule python_bytecode_version__3_7a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.7a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x3e0d0d0a
}

rule python_bytecode_version__3_7a2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.7a2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x3f0d0d0a
}

rule python_bytecode_version__3_7a4 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.7a4"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x400d0d0a
}

rule python_bytecode_version__3_7b1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.7b1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x410d0d0a
}

rule python_bytecode_version__3_7b5 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.7b5"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x420d0d0a
}

rule python_bytecode_version__3_8a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.8a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x480d0d0a or 
        uint32be(0) == 0x490d0d0a or 
        uint32be(0) == 0x520d0d0a
}

rule python_bytecode_version__3_8b2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.8b2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x530d0d0a or 
        uint32be(0) == 0x540d0d0a
}

rule python_bytecode_version__3_8b4 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.8b4"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x550d0d0a
}

rule python_bytecode_version__3_9a0 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.9a0"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x5c0d0d0a or 
        uint32be(0) == 0x5d0d0d0a or 
        uint32be(0) == 0x5e0d0d0a
}

rule python_bytecode_version__3_9a2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.9a2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x5f0d0d0a or 
        uint32be(0) == 0x600d0d0a or 
        uint32be(0) == 0x610d0d0a
}

rule python_bytecode_version__3_10a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.10a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x660d0d0a or 
        uint32be(0) == 0x670d0d0a
}

rule python_bytecode_version__3_10a2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.10a2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x680d0d0a or 
        uint32be(0) == 0x690d0d0a
}

rule python_bytecode_version__3_10a6 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.10a6"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x6a0d0d0a
}

rule python_bytecode_version__3_10a7 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.10a7"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x6b0d0d0a
}

rule python_bytecode_version__3_10b1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.10b1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x6c0d0d0a or 
        uint32be(0) == 0x6d0d0d0a or 
        uint32be(0) == 0x6e0d0d0a or 
        uint32be(0) == 0x6f0d0d0a
}

rule python_bytecode_version__3_11a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.11a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x7a0d0d0a or 
        uint32be(0) == 0x7b0d0d0a or 
        uint32be(0) == 0x7c0d0d0a or 
        uint32be(0) == 0x7d0d0d0a or 
        uint32be(0) == 0x7e0d0d0a or 
        uint32be(0) == 0x7f0d0d0a or 
        uint32be(0) == 0x800d0d0a or 
        uint32be(0) == 0x810d0d0a or 
        uint32be(0) == 0x820d0d0a or 
        uint32be(0) == 0x830d0d0a or 
        uint32be(0) == 0x840d0d0a or 
        uint32be(0) == 0x850d0d0a
}

rule python_bytecode_version__3_11a2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.11a2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x860d0d0a
}

rule python_bytecode_version__3_11a3 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.11a3"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x870d0d0a or 
        uint32be(0) == 0x880d0d0a or 
        uint32be(0) == 0x890d0d0a
}

rule python_bytecode_version__3_11a4 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.11a4"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x8a0d0d0a or 
        uint32be(0) == 0x8b0d0d0a or 
        uint32be(0) == 0x8c0d0d0a or 
        uint32be(0) == 0x8d0d0d0a or 
        uint32be(0) == 0x8e0d0d0a or 
        uint32be(0) == 0x8f0d0d0a or 
        uint32be(0) == 0x900d0d0a or 
        uint32be(0) == 0x910d0d0a or 
        uint32be(0) == 0x920d0d0a
}

rule python_bytecode_version__3_11a5 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.11a5"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x930d0d0a or 
        uint32be(0) == 0x940d0d0a or 
        uint32be(0) == 0x950d0d0a or 
        uint32be(0) == 0x960d0d0a or 
        uint32be(0) == 0x970d0d0a or 
        uint32be(0) == 0x980d0d0a or 
        uint32be(0) == 0x990d0d0a or 
        uint32be(0) == 0x9a0d0d0a or 
        uint32be(0) == 0x9b0d0d0a or 
        uint32be(0) == 0x9c0d0d0a or 
        uint32be(0) == 0x9d0d0d0a
}

rule python_bytecode_version__3_11a6 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.11a6"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x9e0d0d0a or 
        uint32be(0) == 0x9f0d0d0a or 
        uint32be(0) == 0xa00d0d0a or 
        uint32be(0) == 0xa10d0d0a or 
        uint32be(0) == 0xa20d0d0a or 
        uint32be(0) == 0xa30d0d0a
}

rule python_bytecode_version__3_11a7 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.11a7"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xa40d0d0a or 
        uint32be(0) == 0xa50d0d0a or 
        uint32be(0) == 0xa60d0d0a
}

rule python_bytecode_version__3_11b4 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.11b4"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xa70d0d0a
}

rule python_bytecode_version__3_12a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.12a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xac0d0d0a or 
        uint32be(0) == 0xad0d0d0a or 
        uint32be(0) == 0xae0d0d0a or 
        uint32be(0) == 0xaf0d0d0a or 
        uint32be(0) == 0xb00d0d0a or 
        uint32be(0) == 0xb10d0d0a or 
        uint32be(0) == 0xb20d0d0a or 
        uint32be(0) == 0xb30d0d0a or 
        uint32be(0) == 0xb40d0d0a or 
        uint32be(0) == 0xb50d0d0a
}

rule python_bytecode_version__3_12a2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.12a2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xb60d0d0a or 
        uint32be(0) == 0xb70d0d0a or 
        uint32be(0) == 0xb80d0d0a
}

rule python_bytecode_version__3_12a4 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.12a4"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xb90d0d0a or 
        uint32be(0) == 0xba0d0d0a
}

rule python_bytecode_version__3_12a5 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.12a5"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xbb0d0d0a or 
        uint32be(0) == 0xbc0d0d0a or 
        uint32be(0) == 0xbd0d0d0a
}

rule python_bytecode_version__3_12a6 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.12a6"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xbe0d0d0a or 
        uint32be(0) == 0xbf0d0d0a or 
        uint32be(0) == 0xc00d0d0a
}

rule python_bytecode_version__3_12a7 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.12a7"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xc10d0d0a or 
        uint32be(0) == 0xc20d0d0a or 
        uint32be(0) == 0xc30d0d0a or 
        uint32be(0) == 0xc40d0d0a
}

rule python_bytecode_version__3_12b1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.12b1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xc50d0d0a or 
        uint32be(0) == 0xc60d0d0a or 
        uint32be(0) == 0xc70d0d0a or 
        uint32be(0) == 0xc80d0d0a or 
        uint32be(0) == 0xc90d0d0a or 
        uint32be(0) == 0xca0d0d0a or 
        uint32be(0) == 0xcb0d0d0a
}

rule python_bytecode_version__3_13a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.13a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xde0d0d0a or 
        uint32be(0) == 0xdf0d0d0a or 
        uint32be(0) == 0xe00d0d0a or 
        uint32be(0) == 0xe10d0d0a or 
        uint32be(0) == 0xe20d0d0a or 
        uint32be(0) == 0xe30d0d0a or 
        uint32be(0) == 0xe40d0d0a or 
        uint32be(0) == 0xe50d0d0a or 
        uint32be(0) == 0xe60d0d0a or 
        uint32be(0) == 0xe70d0d0a or 
        uint32be(0) == 0xe80d0d0a or 
        uint32be(0) == 0xe90d0d0a or 
        uint32be(0) == 0xea0d0d0a or 
        uint32be(0) == 0xeb0d0d0a or 
        uint32be(0) == 0xec0d0d0a or 
        uint32be(0) == 0xed0d0d0a or 
        uint32be(0) == 0xee0d0d0a or 
        uint32be(0) == 0xef0d0d0a or 
        uint32be(0) == 0xf00d0d0a
}

rule python_bytecode_version__3_13a5 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.13a5"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xf10d0d0a
}

rule python_bytecode_version__3_13a6 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.13a6"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xf20d0d0a
}

rule python_bytecode_version__3_13b1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.13b1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0xf30d0d0a
}

rule python_bytecode_version__3_14a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.14a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x100e0d0a or 
        uint32be(0) == 0x110e0d0a or 
        uint32be(0) == 0x120e0d0a or 
        uint32be(0) == 0x130e0d0a or 
        uint32be(0) == 0x140e0d0a or 
        uint32be(0) == 0x150e0d0a or 
        uint32be(0) == 0x160e0d0a or 
        uint32be(0) == 0x170e0d0a or 
        uint32be(0) == 0x180e0d0a
}

rule python_bytecode_version__3_14a2 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.14a2"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x190e0d0a
}

rule python_bytecode_version__3_14a4 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.14a4"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x1a0e0d0a or 
        uint32be(0) == 0x1b0e0d0a or 
        uint32be(0) == 0x1c0e0d0a or 
        uint32be(0) == 0x1d0e0d0a
}

rule python_bytecode_version__3_14a5 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.14a5"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x1e0e0d0a or 
        uint32be(0) == 0x1f0e0d0a or 
        uint32be(0) == 0x200e0d0a
}

rule python_bytecode_version__3_14a6 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.14a6"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x210e0d0a or 
        uint32be(0) == 0x220e0d0a or 
        uint32be(0) == 0x230e0d0a or 
        uint32be(0) == 0x240e0d0a
}

rule python_bytecode_version__3_14a7 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.14a7"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x250e0d0a or 
        uint32be(0) == 0x260e0d0a or 
        uint32be(0) == 0x270e0d0a
}

rule python_bytecode_version__3_14b1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.14b1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x280e0d0a
}

rule python_bytecode_version__3_15a0 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.15a0"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x420e0d0a
}

rule python_bytecode_version__3_15a1 {
    meta:
        reference = "https://github.com/rakovskij-stanislav/pyc_rules"
        description = "Python bytecode from version 3.15a1"
        author = "Rakovsky Stanislav @ https://t.me/disasm_me_ch"
        license = "MIT"
        date = "2025-07-13" // latest ruleset update
    condition:
        uint32be(0) == 0x430e0d0a or 
        uint32be(0) == 0x440e0d0a or 
        uint32be(0) == 0x450e0d0a
}


"""
test_behavior.py — Unit tests for Layer B behavior chains & taint-lite detection.
"""

import unittest
from javadecompiler.class_parser import ClassInfo, MethodInfo
from javadecompiler.security.behavior import BehaviorDetector


def make_dummy_class(
    class_name: str = "com/example/Malware",
    cp: dict = None,
    methods: dict = None,
) -> ClassInfo:
    return ClassInfo(
        class_name=class_name,
        super_class="java/lang/Object",
        interfaces=[],
        major_version=61,
        minor_version=0,
        constant_pool=cp or {},
        methods=methods or {},
    )


class TestBehaviorChains(unittest.TestCase):
    def test_revshell_chain(self):
        cp = {
            1: {"type": "Class", "nameIndex": 2},
            2: {"type": "Utf8", "value": "java/net/Socket"},
            3: {"type": "NameAndType", "nameIndex": 4, "descriptorIndex": 5},
            4: {"type": "Utf8", "value": "getInputStream"},
            5: {"type": "Utf8", "value": "()Ljava/io/InputStream;"},
            6: {"type": "Ref", "refKind": "MethodRef", "classIndex": 1, "nameAndTypeIndex": 3},
            7: {"type": "Class", "nameIndex": 8},
            8: {"type": "Utf8", "value": "java/lang/Process"},
            9: {"type": "NameAndType", "nameIndex": 10, "descriptorIndex": 11},
            10: {"type": "Utf8", "value": "getOutputStream"},
            11: {"type": "Utf8", "value": "()Ljava/io/OutputStream;"},
            12: {"type": "Ref", "refKind": "MethodRef", "classIndex": 7, "nameAndTypeIndex": 9},
        }
        m_info = MethodInfo(name="spawnShell", descriptor="()V", access_flags=1, bytecode=b"")
        c_info = make_dummy_class(cp=cp, methods={"spawnShell": m_info})

        instrs = [
            {"offset": 0, "mnemonic": "invokevirtual", "operands": [0, 6]},  # Socket.getInputStream
            {"offset": 3, "mnemonic": "invokevirtual", "operands": [0, 12]},  # Process.getOutputStream
        ]

        detector = BehaviorDetector()
        findings = detector.detect_chains(
            c_info,
            raw_methods={"spawnShell": "socket.getInputStream(); process.getOutputStream();"},
            instructions_by_method={"spawnShell": instrs},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ruleId, "JD-CHAIN-REVSHELL")
        self.assertEqual(findings[0].severity, "critical")
        self.assertTrue(any("[SOURCE]" in e.text for e in findings[0].evidence))
        self.assertTrue(any("[SINK]" in e.text for e in findings[0].evidence))

    def test_dropper_chain(self):
        cp = {
            1: {"type": "Class", "nameIndex": 2},
            2: {"type": "Utf8", "value": "java/net/URL"},
            3: {"type": "NameAndType", "nameIndex": 4, "descriptorIndex": 5},
            4: {"type": "Utf8", "value": "openStream"},
            5: {"type": "Utf8", "value": "()Ljava/io/InputStream;"},
            6: {"type": "Ref", "refKind": "MethodRef", "classIndex": 1, "nameAndTypeIndex": 3},
            7: {"type": "Class", "nameIndex": 8},
            8: {"type": "Utf8", "value": "java/lang/Runtime"},
            9: {"type": "NameAndType", "nameIndex": 10, "descriptorIndex": 11},
            10: {"type": "Utf8", "value": "exec"},
            11: {"type": "Utf8", "value": "(Ljava/lang/String;)Ljava/lang/Process;"},
            12: {"type": "Ref", "refKind": "MethodRef", "classIndex": 7, "nameAndTypeIndex": 9},
            13: {"type": "Class", "nameIndex": 14},
            14: {"type": "Utf8", "value": "java/io/FileOutputStream"},
            15: {"type": "NameAndType", "nameIndex": 16, "descriptorIndex": 17},
            16: {"type": "Utf8", "value": "write"},
            17: {"type": "Utf8", "value": "([B)V"},
            18: {"type": "Ref", "refKind": "MethodRef", "classIndex": 13, "nameAndTypeIndex": 15},
        }
        m_info = MethodInfo(name="dropPayload", descriptor="()V", access_flags=1, bytecode=b"")
        c_info = make_dummy_class(cp=cp, methods={"dropPayload": m_info})

        instrs = [
            {"offset": 0, "mnemonic": "invokevirtual", "operands": [0, 6]},  # openStream
            {"offset": 3, "mnemonic": "invokevirtual", "operands": [0, 18]},  # FileOutputStream.write
            {"offset": 6, "mnemonic": "invokevirtual", "operands": [0, 12]},  # Runtime.exec
        ]

        detector = BehaviorDetector()
        findings = detector.detect_chains(
            c_info,
            raw_methods={"dropPayload": "url.openStream(); fos.write(buf); Runtime.getRuntime().exec(path);"},
            instructions_by_method={"dropPayload": instrs},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ruleId, "JD-CHAIN-DROPPER")

    def test_decode_exec_chain(self):
        cp = {
            1: {"type": "Class", "nameIndex": 2},
            2: {"type": "Utf8", "value": "java/util/Base64$Decoder"},
            3: {"type": "NameAndType", "nameIndex": 4, "descriptorIndex": 5},
            4: {"type": "Utf8", "value": "decode"},
            5: {"type": "Utf8", "value": "(Ljava/lang/String;)[B"},
            6: {"type": "Ref", "refKind": "MethodRef", "classIndex": 1, "nameAndTypeIndex": 3},
            7: {"type": "Class", "nameIndex": 8},
            8: {"type": "Utf8", "value": "java/lang/Runtime"},
            9: {"type": "NameAndType", "nameIndex": 10, "descriptorIndex": 11},
            10: {"type": "Utf8", "value": "exec"},
            11: {"type": "Utf8", "value": "(Ljava/lang/String;)Ljava/lang/Process;"},
            12: {"type": "Ref", "refKind": "MethodRef", "classIndex": 7, "nameAndTypeIndex": 9},
        }
        m_info = MethodInfo(name="unpack", descriptor="()V", access_flags=1, bytecode=b"")
        c_info = make_dummy_class(cp=cp, methods={"unpack": m_info})

        instrs = [
            {"offset": 0, "mnemonic": "invokevirtual", "operands": [0, 6]},  # Base64.decode
            {"offset": 3, "mnemonic": "invokevirtual", "operands": [0, 12]},  # exec
        ]

        detector = BehaviorDetector()
        findings = detector.detect_chains(
            c_info,
            raw_methods={"unpack": "Base64.getDecoder().decode(str); Runtime.getRuntime().exec(decoded);"},
            instructions_by_method={"unpack": instrs},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ruleId, "JD-CHAIN-DECODE-EXEC")

    def test_taint_sink_chain(self):
        cp = {
            1: {"type": "Class", "nameIndex": 2},
            2: {"type": "Utf8", "value": "java/lang/StringBuilder"},
            3: {"type": "NameAndType", "nameIndex": 4, "descriptorIndex": 5},
            4: {"type": "Utf8", "value": "append"},
            5: {"type": "Utf8", "value": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"},
            6: {"type": "Ref", "refKind": "MethodRef", "classIndex": 1, "nameAndTypeIndex": 3},
            7: {"type": "Class", "nameIndex": 8},
            8: {"type": "Utf8", "value": "java/sql/Statement"},
            9: {"type": "NameAndType", "nameIndex": 10, "descriptorIndex": 11},
            10: {"type": "Utf8", "value": "executeQuery"},
            11: {"type": "Utf8", "value": "(Ljava/lang/String;)Ljava/sql/ResultSet;"},
            12: {"type": "Ref", "refKind": "MethodRef", "classIndex": 7, "nameAndTypeIndex": 9},
        }
        m_info = MethodInfo(
            name="queryUser",
            descriptor="(Ljava/lang/String;)V",
            access_flags=9,  # public static
            param_types=["String"],
            bytecode=b"",
        )
        c_info = make_dummy_class(cp=cp, methods={"queryUser": m_info})

        instrs = [
            {"offset": 0, "mnemonic": "aload_0", "operands": []},  # parameter read
            {"offset": 1, "mnemonic": "invokevirtual", "operands": [0, 6]},  # StringBuilder.append
            {"offset": 4, "mnemonic": "invokeinterface", "operands": [0, 12]},  # Statement.executeQuery
        ]

        detector = BehaviorDetector()
        findings = detector.detect_chains(
            c_info,
            raw_methods={"queryUser": "sb.append(param0); stmt.executeQuery(sb.toString());"},
            instructions_by_method={"queryUser": instrs},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ruleId, "JD-CHAIN-TAINT-SINK")

    def test_clinit_chain(self):
        cp = {
            1: {"type": "Class", "nameIndex": 2},
            2: {"type": "Utf8", "value": "com/example/Malware"},
            3: {"type": "NameAndType", "nameIndex": 4, "descriptorIndex": 5},
            4: {"type": "Utf8", "value": "initHelper"},
            5: {"type": "Utf8", "value": "()V"},
            6: {"type": "Ref", "refKind": "MethodRef", "classIndex": 1, "nameAndTypeIndex": 3},
            7: {"type": "Class", "nameIndex": 8},
            8: {"type": "Utf8", "value": "java/net/Socket"},
            9: {"type": "NameAndType", "nameIndex": 10, "descriptorIndex": 11},
            10: {"type": "Utf8", "value": "<init>"},
            11: {"type": "Utf8", "value": "(Ljava/lang/String;I)V"},
            12: {"type": "Ref", "refKind": "MethodRef", "classIndex": 7, "nameAndTypeIndex": 9},
        }
        m_clinit = MethodInfo(name="<clinit>", descriptor="()V", access_flags=8, bytecode=b"")
        m_helper = MethodInfo(name="initHelper", descriptor="()V", access_flags=10, bytecode=b"")
        c_info = make_dummy_class(cp=cp, methods={"<clinit>": m_clinit, "initHelper": m_helper})

        instrs_clinit = [{"offset": 0, "mnemonic": "invokestatic", "operands": [0, 6]}]
        instrs_helper = [{"offset": 0, "mnemonic": "invokespecial", "operands": [0, 12]}]

        detector = BehaviorDetector()
        findings = detector.detect_chains(
            c_info,
            raw_methods={"<clinit>": "initHelper();", "initHelper": "new Socket(host, port);"},
            instructions_by_method={"<clinit>": instrs_clinit, "initHelper": instrs_helper},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].ruleId, "JD-CHAIN-CLINIT")
        self.assertEqual(findings[0].severity, "critical")


if __name__ == "__main__":
    unittest.main()

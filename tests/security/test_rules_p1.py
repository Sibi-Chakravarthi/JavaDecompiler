"""
test_rules_p1.py — Unit tests for Milestone 3 static rules (execution, network, dynamic, deserialization, crypto).
"""

import unittest
from javadecompiler.class_parser import ClassInfo, MethodInfo
from javadecompiler.security.rules.base import get_rule
import javadecompiler.security.rules  # triggers registration


def make_dummy_class(
    class_name: str = "com/example/TestClass",
    super_class: str = "java/lang/Object",
    cp: dict = None,
    methods: dict = None,
) -> ClassInfo:
    return ClassInfo(
        class_name=class_name,
        super_class=super_class,
        interfaces=[],
        major_version=61,
        minor_version=0,
        constant_pool=cp or {},
        methods=methods or {},
    )


class TestStaticRulesPart1(unittest.TestCase):
    def test_jd_exec_dynamic_and_constant(self):
        cp = {
            1: {"type": "Class", "nameIndex": 2},
            2: {"type": "Utf8", "value": "java/lang/Runtime"},
            3: {"type": "NameAndType", "nameIndex": 4, "descriptorIndex": 5},
            4: {"type": "Utf8", "value": "exec"},
            5: {"type": "Utf8", "value": "(Ljava/lang/String;)Ljava/lang/Process;"},
            6: {"type": "Ref", "refKind": "MethodRef", "classIndex": 1, "nameAndTypeIndex": 3},
            7: {"type": "String", "stringIndex": 8},
            8: {"type": "Utf8", "value": "calc.exe"},
            9: {"type": "String", "stringIndex": 10},
            10: {"type": "Utf8", "value": "/bin/sh"},
        }
        c_info = make_dummy_class(cp=cp)
        m_info = MethodInfo(
            name="runCmd",
            descriptor="(Ljava/lang/String;)V",
            access_flags=1,
            bytecode=b"",
        )

        # Dynamic: aload_1 then invokevirtual Runtime.exec
        instr_dyn = [
            {"offset": 0, "mnemonic": "aload_1", "operands": []},
            {"offset": 1, "mnemonic": "invokevirtual", "operands": [0, 6]},
        ]
        r1 = get_rule("JD-EXEC-001")
        f1 = r1.analyze_method(c_info, "runCmd", m_info, ["Runtime.getRuntime().exec(param0);"], instr_dyn)
        self.assertEqual(len(f1), 1)
        self.assertEqual(f1[0].ruleId, "JD-EXEC-001")
        self.assertEqual(f1[0].severity, "high")

        # Constant: ldc "calc.exe" then invokevirtual Runtime.exec
        instr_const = [
            {"offset": 0, "mnemonic": "ldc", "operands": [7]},
            {"offset": 2, "mnemonic": "invokevirtual", "operands": [0, 6]},
        ]
        r2 = get_rule("JD-EXEC-002")
        f2 = r2.analyze_method(c_info, "runCmd", m_info, ['Runtime.getRuntime().exec("calc.exe");'], instr_const)
        self.assertEqual(len(f2), 1)
        self.assertEqual(f2[0].ruleId, "JD-EXEC-002")
        self.assertEqual(f2[0].severity, "low")

        # Shell invocation: has exec and /bin/sh in CP
        r3 = get_rule("JD-EXEC-003")
        f3 = r3.analyze_method(c_info, "runCmd", m_info, ["Runtime.getRuntime().exec(cmd);"], instr_dyn)
        self.assertEqual(len(f3), 1)
        self.assertEqual(f3[0].ruleId, "JD-EXEC-003")

    def test_jd_net_rules(self):
        cp = {
            1: {"type": "Class", "nameIndex": 2},
            2: {"type": "Utf8", "value": "java/net/Socket"},
            3: {"type": "Utf8", "value": "198.51.100.25"},
            4: {"type": "String", "stringIndex": 3},
            5: {"type": "Utf8", "value": "http://evil-c2.onion/beacon"},
            6: {"type": "String", "stringIndex": 5},
            7: {"type": "Class", "nameIndex": 8},
            8: {"type": "Utf8", "value": "java/net/InetAddress"},
            9: {"type": "NameAndType", "nameIndex": 10, "descriptorIndex": 11},
            10: {"type": "Utf8", "value": "getByName"},
            11: {"type": "Utf8", "value": "(Ljava/lang/String;)Ljava/net/InetAddress;"},
            12: {"type": "Ref", "refKind": "MethodRef", "classIndex": 7, "nameAndTypeIndex": 9},
        }
        c_info = make_dummy_class(cp=cp)
        m_info = MethodInfo(name="connect", descriptor="()V", access_flags=1, bytecode=b"")

        # JD-NET-001 (raw socket)
        instr_sock = [
            {"offset": 0, "mnemonic": "new", "operands": [0, 1]},
            {"offset": 3, "mnemonic": "dup", "operands": []},
        ]
        r_net1 = get_rule("JD-NET-001")
        f_net1 = r_net1.analyze_method(c_info, "connect", m_info, ["new Socket()"], instr_sock)
        self.assertEqual(len(f_net1), 1)
        self.assertEqual(f_net1[0].ruleId, "JD-NET-001")

        # JD-NET-002 (suspicious host in CP)
        r_net2 = get_rule("JD-NET-002")
        f_net2 = r_net2.analyze_class(c_info)
        self.assertTrue(any(f.ruleId == "JD-NET-002" for f in f_net2))

        # JD-NET-003 (DNS exfiltration)
        instr_dns = [
            {"offset": 0, "mnemonic": "aload_1", "operands": []},
            {"offset": 1, "mnemonic": "invokestatic", "operands": [0, 12]},
        ]
        r_net3 = get_rule("JD-NET-003")
        f_net3 = r_net3.analyze_method(c_info, "connect", m_info, ["InetAddress.getByName(x)"], instr_dns)
        self.assertEqual(len(f_net3), 1)
        self.assertEqual(f_net3[0].ruleId, "JD-NET-003")

    def test_jd_dynamic_rules(self):
        cp = {
            1: {"type": "Class", "nameIndex": 2},
            2: {"type": "Utf8", "value": "java/net/URLClassLoader"},
            3: {"type": "Class", "nameIndex": 4},
            4: {"type": "Utf8", "value": "javax/naming/InitialContext"},
            5: {"type": "NameAndType", "nameIndex": 6, "descriptorIndex": 7},
            6: {"type": "Utf8", "value": "lookup"},
            7: {"type": "Utf8", "value": "(Ljava/lang/String;)Ljava/lang/Object;"},
            8: {"type": "Ref", "refKind": "MethodRef", "classIndex": 3, "nameAndTypeIndex": 5},
            9: {"type": "Class", "nameIndex": 10},
            10: {"type": "Utf8", "value": "java/lang/reflect/AccessibleObject"},
            11: {"type": "NameAndType", "nameIndex": 12, "descriptorIndex": 13},
            12: {"type": "Utf8", "value": "setAccessible"},
            13: {"type": "Utf8", "value": "(Z)V"},
            14: {"type": "Ref", "refKind": "MethodRef", "classIndex": 9, "nameAndTypeIndex": 11},
        }
        c_info = make_dummy_class(super_class="java/lang/ClassLoader", cp=cp)
        m_info = MethodInfo(name="load", descriptor="()V", access_flags=1, bytecode=b"")

        # JD-DYN-001 (ClassLoader subclass + URLClassLoader)
        r_dyn1 = get_rule("JD-DYN-001")
        f_dyn1_cls = r_dyn1.analyze_class(c_info)
        self.assertTrue(any(f.ruleId == "JD-DYN-001" for f in f_dyn1_cls))

        instr_url = [{"offset": 0, "mnemonic": "new", "operands": [0, 1]}]
        f_dyn1_m = r_dyn1.analyze_method(c_info, "load", m_info, ["new URLClassLoader()"], instr_url)
        self.assertEqual(len(f_dyn1_m), 1)

        # JD-DYN-002 (setAccessible)
        r_dyn2 = get_rule("JD-DYN-002")
        instr_acc = [{"offset": 0, "mnemonic": "invokevirtual", "operands": [0, 14]}]
        f_dyn2 = r_dyn2.analyze_method(c_info, "load", m_info, ["field.setAccessible(true)"], instr_acc)
        self.assertEqual(len(f_dyn2), 1)

        # JD-DYN-003 (JNDI lookup)
        r_dyn3 = get_rule("JD-DYN-003")
        instr_jndi = [{"offset": 0, "mnemonic": "invokevirtual", "operands": [0, 8]}]
        f_dyn3 = r_dyn3.analyze_method(c_info, "load", m_info, ["ctx.lookup(uri)"], instr_jndi)
        self.assertEqual(len(f_dyn3), 1)
        self.assertEqual(f_dyn3[0].severity, "critical")

    def test_jd_deserialization_rules(self):
        cp = {
            1: {"type": "Class", "nameIndex": 2},
            2: {"type": "Utf8", "value": "java/io/ObjectInputStream"},
            3: {"type": "NameAndType", "nameIndex": 4, "descriptorIndex": 5},
            4: {"type": "Utf8", "value": "readObject"},
            5: {"type": "Utf8", "value": "()Ljava/lang/Object;"},
            6: {"type": "Ref", "refKind": "MethodRef", "classIndex": 1, "nameAndTypeIndex": 3},
            7: {"type": "Class", "nameIndex": 8},
            8: {"type": "Utf8", "value": "java/beans/XMLDecoder"},
            9: {"type": "Ref", "refKind": "MethodRef", "classIndex": 7, "nameAndTypeIndex": 3},
        }
        c_info = make_dummy_class(cp=cp)
        m_info = MethodInfo(name="deser", descriptor="()V", access_flags=1, bytecode=b"")

        # JD-DESER-001 (ObjectInputStream.readObject)
        r_deser1 = get_rule("JD-DESER-001")
        instr1 = [{"offset": 0, "mnemonic": "invokevirtual", "operands": [0, 6]}]
        f_deser1 = r_deser1.analyze_method(c_info, "deser", m_info, ["ois.readObject()"], instr1)
        self.assertEqual(len(f_deser1), 1)
        self.assertEqual(f_deser1[0].ruleId, "JD-DESER-001")

        # JD-DESER-002 (XMLDecoder.readObject)
        r_deser2 = get_rule("JD-DESER-002")
        instr2 = [{"offset": 0, "mnemonic": "invokevirtual", "operands": [0, 9]}]
        f_deser2 = r_deser2.analyze_method(c_info, "deser", m_info, ["xmlDecoder.readObject()"], instr2)
        self.assertEqual(len(f_deser2), 1)
        self.assertEqual(f_deser2[0].ruleId, "JD-DESER-002")

    def test_jd_crypto_rules(self):
        cp = {
            1: {"type": "Class", "nameIndex": 2},
            2: {"type": "Utf8", "value": "java/security/MessageDigest"},
            3: {"type": "NameAndType", "nameIndex": 4, "descriptorIndex": 5},
            4: {"type": "Utf8", "value": "getInstance"},
            5: {"type": "Utf8", "value": "(Ljava/lang/String;)Ljava/security/MessageDigest;"},
            6: {"type": "Ref", "refKind": "MethodRef", "classIndex": 1, "nameAndTypeIndex": 3},
            7: {"type": "String", "stringIndex": 8},
            8: {"type": "Utf8", "value": "MD5"},
            9: {"type": "Class", "nameIndex": 10},
            10: {"type": "Utf8", "value": "javax/crypto/Cipher"},
            11: {"type": "NameAndType", "nameIndex": 4, "descriptorIndex": 12},
            12: {"type": "Utf8", "value": "(Ljava/lang/String;)Ljavax/crypto/Cipher;"},
            13: {"type": "Ref", "refKind": "MethodRef", "classIndex": 9, "nameAndTypeIndex": 11},
            14: {"type": "String", "stringIndex": 15},
            15: {"type": "Utf8", "value": "DES/ECB/PKCS5Padding"},
            16: {"type": "Class", "nameIndex": 17},
            17: {"type": "Utf8", "value": "java/util/Random"},
        }
        c_info = make_dummy_class(cp=cp)
        m_info = MethodInfo(name="hashPassword", descriptor="()V", access_flags=1, bytecode=b"")

        # JD-CRYP-001 (MD5)
        r_cryp1 = get_rule("JD-CRYP-001")
        instr_hash = [
            {"offset": 0, "mnemonic": "ldc", "operands": [7]},
            {"offset": 2, "mnemonic": "invokestatic", "operands": [0, 6]},
        ]
        f_cryp1 = r_cryp1.analyze_method(c_info, "hashPassword", m_info, ['MessageDigest.getInstance("MD5")'], instr_hash)
        self.assertEqual(len(f_cryp1), 1)

        # JD-CRYP-002 (DES/ECB)
        r_cryp2 = get_rule("JD-CRYP-002")
        instr_ciph = [
            {"offset": 0, "mnemonic": "ldc", "operands": [14]},
            {"offset": 2, "mnemonic": "invokestatic", "operands": [0, 13]},
        ]
        f_cryp2 = r_cryp2.analyze_method(c_info, "hashPassword", m_info, ['Cipher.getInstance("DES/ECB/PKCS5Padding")'], instr_ciph)
        self.assertEqual(len(f_cryp2), 1)

        # JD-CRYP-004 (Random in password context)
        r_cryp4 = get_rule("JD-CRYP-004")
        instr_rnd = [{"offset": 0, "mnemonic": "new", "operands": [0, 16]}]
        f_cryp4 = r_cryp4.analyze_method(c_info, "generateToken", m_info, ["new Random()"], instr_rnd)
        self.assertEqual(len(f_cryp4), 1)

        # JD-CRYP-005 (HostnameVerifier returning true)
        m_verify = MethodInfo(name="verify", descriptor="(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z", access_flags=1, bytecode=b"")
        instr_tls = [
            {"offset": 0, "mnemonic": "iconst_1", "operands": []},
            {"offset": 1, "mnemonic": "ireturn", "operands": []},
        ]
        r_cryp5 = get_rule("JD-CRYP-005")
        f_cryp5 = r_cryp5.analyze_method(c_info, "verify", m_verify, ["return true;"], instr_tls)
        self.assertEqual(len(f_cryp5), 1)
        self.assertEqual(f_cryp5[0].ruleId, "JD-CRYP-005")


if __name__ == "__main__":
    unittest.main()

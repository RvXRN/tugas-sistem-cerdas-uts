from experta import Fact

class AttackSymptom(Fact):
    """
    Representasi satu gejala serangan sebagai Fact.
    
    Contoh penggunaan:
        AttackSymptom(name="port_scanning", intensity="high")
    """
    pass

class TargetSystem(Fact):
    """Fakta tentang sistem yang menjadi target."""
    pass

class DetectedAttack(Fact):
    """
    Fakta yang di-assert oleh rules ketika serangan terdeteksi.
    Engine akan mengumpulkan semua Fact jenis ini sebagai hasil akhir.
    """
    pass

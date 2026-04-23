import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

def test_import():
    import android_llm_capture as alc
    assert hasattr(alc, 'LLMCapture')

def test_captured_call():
    import android_llm_capture as alc
    assert hasattr(alc, 'CapturedCall')

def test_list_devices():
    import android_llm_capture as alc
    assert callable(alc.list_devices)

def test_list_packages():
    import android_llm_capture as alc
    assert callable(alc.list_packages)

# convert_to_onnx.py
import os
import argparse
import json
import joblib

from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType


def infer_n_features(model):
    """พยายามเดาจำนวนฟีเจอร์จากโมเดล sklearn"""
    n = getattr(model, "n_features_in_", None)
    if n is not None:
        return int(n)

    coef = getattr(model, "coef_", None)
    if coef is not None:
        try:
            import numpy as _np
            arr = _np.asarray(coef)
            return int(arr.shape[-1] if arr.ndim > 1 else arr.shape[0])
        except Exception:
            pass

    fi = getattr(model, "feature_importances_", None)
    if fi is not None:
        try:
            return int(len(fi))
        except Exception:
            pass

    # pipeline -> ลองดู estimator สุดท้าย
    try:
        from sklearn.pipeline import Pipeline
        if isinstance(model, Pipeline):
            return infer_n_features(model.steps[-1][1])
    except Exception:
        pass

    return None


def get_final_estimator(model):
    """คืน estimator ตัวสุดท้าย (รองรับ Pipeline)"""
    try:
        from sklearn.pipeline import Pipeline
        if isinstance(model, Pipeline):
            return model.steps[-1][1]
    except Exception:
        pass
    return model


def verify_no_zipmap(onnx_path):
    """ตรวจสอบว่าในกราฟ ONNX ไม่มีโหนด ZipMap (เพื่อหลีกเลี่ยง output แบบ map)"""
    try:
        import onnx
    except Exception:
        print("⚠️ Skipping structural verify: onnx package not available.")
        return

    model = onnx.load(onnx_path)
    has_zipmap = any(n.op_type == "ZipMap" for n in model.graph.node)
    if has_zipmap:
        print("❌ ZipMap FOUND in graph. This may break onnxruntime-web when reading probabilities.")
    else:
        print("✅ Verified: No ZipMap node in the ONNX graph.")


def main():
    parser = argparse.ArgumentParser(description="Convert sklearn .pkl to ONNX (ZipMap disabled)")
    parser.add_argument("--pkl", required=True, help="Path to extension.pkl")
    parser.add_argument("--feat", required=False, help="Path to extension_feature_order.json (optional)")
    parser.add_argument("--out", required=False, default=None, help="Output ONNX path (optional)")
    parser.add_argument("--opset", type=int, default=13, help="Target opset (default: 13)")
    parser.add_argument("--verify", action="store_true", help="Verify that ONNX has no ZipMap node")
    args = parser.parse_args()

    pkl_path = os.path.abspath(args.pkl)
    if not os.path.isfile(pkl_path):
        raise FileNotFoundError(f"PKL file not found: {pkl_path}")

    out_dir = os.path.dirname(pkl_path)
    if args.out:
        onnx_out = args.out if os.path.isabs(args.out) else os.path.abspath(os.path.join(out_dir, args.out))
    else:
        onnx_out = os.path.join(out_dir, "extension.onnx")

    os.makedirs(os.path.dirname(onnx_out), exist_ok=True)

    print(f"📦 Loading model from: {pkl_path}")
    clf = joblib.load(pkl_path)

    # อ่านลำดับฟีเจอร์ (ถ้ามี)
    feat_order = None
    n_features = None
    if args.feat:
        feat_path = os.path.abspath(args.feat)
        if os.path.isfile(feat_path):
            with open(feat_path, "r", encoding="utf-8") as f:
                feat_order = json.load(f)
            n_features = len(feat_order)
            print(f"✅ Feature order loaded: {n_features} features from {feat_path}")
        else:
            print("⚠️ Feature order file not found, will try to infer from model.")

    if n_features is None:
        n_features = infer_n_features(clf)
        if n_features is not None:
            print(f"✅ Inferred n_features from model: {n_features}")
        else:
            print("⚠️ Could not infer number of features. Use --feat to provide exact order. Fallback n_features=10.")
            n_features = 10

    # กำหนด input type
    initial_type = [("float_input", FloatTensorType([None, int(n_features)]))]

    # ปิด ZipMap ของ estimator สุดท้ายเพื่อให้ prob เป็น tensor (ไม่ใช่ map)
    final_est = get_final_estimator(clf)
    options = {id(final_est): {"zipmap": False}}

    print(f"🚧 Converting to ONNX (opset={args.opset}, zipmap=False) ...")
    onnx_model = convert_sklearn(
        clf,
        clf.__class__.__name__,
        initial_types=initial_type,
        options=options,
        target_opset=args.opset,
    )

    with open(onnx_out, "wb") as f:
        f.write(onnx_model.SerializeToString())

    print(f"💾 Saved ONNX model to: {onnx_out}")

    if args.verify:
        verify_no_zipmap(onnx_out)
        print("✅ Basic verify done.")


if __name__ == "__main__":
    main()

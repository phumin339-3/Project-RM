# convert_to_onnx.py (fixed & improved)
import os
import argparse
import joblib
import json
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

def infer_n_features(model):
    # common sklearn attribute
    n = getattr(model, "n_features_in_", None)
    if n is not None:
        return int(n)
    # try coef_ (linear models)
    coef = getattr(model, "coef_", None)
    if coef is not None:
        try:
            # coef_ can be (n_targets, n_features) or (n_features,)
            import numpy as _np
            arr = _np.asarray(coef)
            if arr.ndim == 1:
                return int(arr.shape[0])
            else:
                return int(arr.shape[-1])
        except Exception:
            pass
    # try feature_importances_ (tree)
    fi = getattr(model, "feature_importances_", None)
    if fi is not None:
        try:
            return int(len(fi))
        except Exception:
            pass
    # pipeline: try to find final estimator
    try:
        from sklearn.pipeline import Pipeline
        if isinstance(model, Pipeline):
            return infer_n_features(model.steps[-1][1])
    except Exception:
        pass
    # fallback default
    return None

def main():
    parser = argparse.ArgumentParser(description="Convert sklearn .pkl to ONNX")
    parser.add_argument("--pkl", required=True, help="Path to extension.pkl")
    parser.add_argument("--feat", required=False, help="Path to extension_feature_order.json (optional)")
    parser.add_argument("--out", required=False, default=None, help="Output ONNX path (optional)")
    args = parser.parse_args()

    pkl_path = os.path.abspath(args.pkl)
    if not os.path.isfile(pkl_path):
        raise FileNotFoundError(f"PKL file not found: {pkl_path}")

    out_dir = os.path.dirname(pkl_path)

    # resolve out path: if provided absolute -> use it; if relative -> interpret relative to pkl folder
    if args.out:
        if os.path.isabs(args.out):
            onnx_out = args.out
        else:
            onnx_out = os.path.abspath(os.path.join(out_dir, args.out))
    else:
        onnx_out = os.path.join(out_dir, "extension.onnx")

    os.makedirs(os.path.dirname(onnx_out), exist_ok=True)

    print("Loading model from:", pkl_path)
    clf = joblib.load(pkl_path)

    feat_order = None
    n_features = None
    if args.feat:
        feat_path = os.path.abspath(args.feat)
        if os.path.isfile(feat_path):
            with open(feat_path, "r", encoding="utf-8") as f:
                feat_order = json.load(f)
            n_features = len(feat_order)
            print(f"Feature order loaded ({n_features} features) from {feat_path}")
        else:
            print("Feature order file not found, will try to infer features from model.")

    if n_features is None:
        n_features = infer_n_features(clf)
        if n_features is not None:
            print(f"Inferred n_features from model: {n_features}")
        else:
            # final fallback: ask user to provide --feat; but we must continue with a safe default
            print("Could not infer number of features from model. Use --feat to provide exact feature order.")
            print("Falling back to n_features = 10 (may be incorrect).")
            n_features = 10

    initial_type = [("float_input", FloatTensorType([None, int(n_features)]))]

    print("Converting to ONNX ...")
    onnx_model = convert_sklearn(clf, clf.__class__.__name__, initial_types=initial_type)

    with open(onnx_out, "wb") as f:
        f.write(onnx_model.SerializeToString())

    print("Saved ONNX model to:", onnx_out)

if __name__ == "__main__":
    main()

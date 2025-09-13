import argparse, os, json
from PIL import Image
from utils import ensure_dirs, compute_hashes

def build_db(images_dir: str, out_path: str):
    ensure_dirs(os.path.dirname(out_path))
    db = {}
    for root, _, files in os.walk(images_dir):
        for fname in files:
            fp = os.path.join(root, fname)
            if fname.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                try:
                    with Image.open(fp) as im:
                        im = im.convert("RGB")
                        hashes = compute_hashes(im)
                        db[fp] = hashes
                except Exception:
                    continue
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    print(f"Wrote {len(db)} entries to {out_path}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--images", required=True, help="Folder with known images")
    ap.add_argument("--out", default="db/hashes.json", help="Path to write hash DB")
    args = ap.parse_args()
    build_db(args.images, args.out)

from pathlib import Path

from src.index import build_index


if __name__ == "__main__":
    app_dir = Path(__file__).resolve().parent
    pdf_path = app_dir / "policy" / "security-control-policy.pdf"
    data_dir = app_dir / "data"
    build_index(policy_pdf_path=pdf_path, data_dir=data_dir)
    print(f"Built index in {data_dir}")


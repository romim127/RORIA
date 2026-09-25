import os

os.environ.setdefault("SKYEYE_RELATIONAL_STANDALONE", "1")

from app.api import app  # noqa: E402


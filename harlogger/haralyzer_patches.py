from functools import cached_property
from typing import Optional

from haralyzer.http import Response


class ResponseHook(Response):
    @cached_property
    def text(self) -> Optional[str]:
        """
        :return: Response body
        :rtype: str
        """
        content = self.raw_entry["content"]
        return content.get("_textBase64", content.get("text"))


def add_text_base64_support_for_haralyzer() -> None:
    setattr(Response, 'text', ResponseHook.text)


class CursorResult:

    # 返回当前游标对应集合中，第一个文档
    # 集合为空，则返回 None
    @staticmethod
    def one(cursor):
        if cursor is not None:
            docs = list(cursor)
            if len(docs) != 0:
                return docs[0]
        return None

    # 返回当前游标对应集合中，所有文档的列表
    # 集合为空，则返回空列表： []
    @staticmethod
    def many(cursor):
        if cursor is not None:
            docs = list(cursor)
            return docs
        return []

import utils.sys.config

# 任务集合
tasks_coll = utils.sys.config.g_tasks_coll


class TasksDAO:

    @staticmethod
    def save(task_info):
        tasks_coll.update_one({'task_id': task_info['task_id']}, {'$set': task_info}, True)

    @staticmethod
    def find(task_id):
        cursor = tasks_coll.find({'task_id': task_id}, {'_id': 0})
        if cursor is not None:
            docs = list(cursor)
            if len(docs) != 0:
                return docs[0]
        return None

    @staticmethod
    def search_by_pack(pack_id):
        cursor = tasks_coll.find({'pack_id': pack_id}, {'_id': 0})
        if cursor is not None:
            docs = list(cursor)
            return docs
        return None

    @staticmethod
    def search_by_file(file_id):
        cursor = tasks_coll.find({'file_id': file_id}, {'_id': 0})
        if cursor is not None:
            docs = list(cursor)
            return docs
        return None

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

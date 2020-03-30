import utils.sys.config

redis = utils.sys.config.g_redis_client


class MyRedis:

    @staticmethod
    def get_real_key(category, key):
        if category is None or len(category) == 0:
            return key
        else:
            return '_'.join([category, key])

    @staticmethod
    def set(key, val, category=''):
        real_key = MyRedis.get_real_key(category, key)
        redis.set(real_key, str(val))

    @staticmethod
    def get(key, category=''):
        real_key = MyRedis.get_real_key(category, key)
        if not redis.exists(real_key):
            return None
        # val = redis.get(real_key)
        # val_r = eval(val)
        return eval(redis.get(real_key))

    @staticmethod
    def delete(key, category=''):
        real_key = MyRedis.get_real_key(category, key)
        redis.delete(real_key)


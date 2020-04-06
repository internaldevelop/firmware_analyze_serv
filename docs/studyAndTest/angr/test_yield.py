
def test_yield():
    def count_down(n):
        print('倒计时：%s' % n)
        while n > 0:
            yield n
            n -= 1
        return
    c = count_down(10)
    for i in count_down(10):
        print(i)
    return


if __name__ == "__main__":
    test_yield()

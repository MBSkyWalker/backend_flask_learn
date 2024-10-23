def remove_duplicates(nums):
    for i in range(1, len(nums)):
        j = i - 1
        print(nums[j])

print(remove_duplicates([1, 1, 1, 2, 3, 3, 4, 4, 5, 5]))
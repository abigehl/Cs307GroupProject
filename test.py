import re
key_words = 'chinese '

remove_list = ['with', 'the']
keywords = key_words
keywords = re.sub(r'\b\w{1,2}\b', '', keywords)
keywords = keywords.split()
keywords = ' '.join([i for i in keywords if i not in remove_list])
output = []
for i in keywords.split():
    for z in range(0, len(i) - 1):
        element = i[z:len(i)]
        print(z)
        output.append(element)
keywords = ' '.join(word for word in output)
keywords = re.sub(r'\b\w{1,1}\b', '', keywords)
keywords = keywords.split()
keywords = ["'%" + x + "%'" for x in keywords]
keywords = ' OR '.join(keywords)

print(keywords)

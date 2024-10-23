def check_comment(body):
    bad_words_dict = {"eng":['fuck', 'bitch', 'shit', 'looser', 'idiot', 'nigger'],
                      'ukr':['єбав', 'хуй', 'пізда', 'шлюха']}
    words = body.replace('.', '').lower().split(" ")
    print(words)
    
    for word in words:
        if word in bad_words_dict['eng'] or word in bad_words_dict['ukr']:
            return f'Be polite to people - don`t use derogatory words. ({word})'


print(check_comment('Шлюха. sfsf sdfsd'))
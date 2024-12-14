import os
import json

class LocalStorage:
    def __init__(self, directory='.data'):
        self.directory = directory
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)

    def _get_file_path(self, key):
        return os.path.join(self.directory, f'{key}.json')

    def set(self, key, value):
        file_path = self._get_file_path(key)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(value, f)

    def get(self, key):
        file_path = self._get_file_path(key)
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            return None

    def remove(self, key):
        file_path = self._get_file_path(key)
        if os.path.exists(file_path):
            os.remove(file_path)

    def clear(self):
        for file_name in os.listdir(self.directory):
            file_path = os.path.join(self.directory, file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)

if __name__ == "__main__":
    local_storage = LocalStorage()

    local_storage.set('username', 'john_doe')
    local_storage.set('age', 30)

    username = local_storage.get('username')
    print(f"Username: {username}")

    #local_storage.remove('age')

    #local_storage.clear()


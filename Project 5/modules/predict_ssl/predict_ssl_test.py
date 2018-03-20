from pathlib2 import Path
import os
import numpy as np
import csv

dir_path = Path(os.path.dirname(os.path.realpath(__file__)))


def predict_app(model_file_name, to_predict_matrix):
    cost = np.inf
    app_name = 'Not found'

    with model_file_name.open(mode='r') as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            model_sample = np.fromstring(','.join(row[1:]), dtype=float, sep=',')
            model_sample_name = row[0]

            new_cost = np.linalg.norm(model_sample - to_predict_matrix)
            if new_cost < cost:
                cost = new_cost
                app_name = model_sample_name

    return app_name, cost


if __name__ == '__main__':
    test_out = open(str(dir_path) + '/samples/test_data.csv')


    true_positive = 0
    total = 6 * 5

    test_reader = csv.reader(test_out, delimiter=',')
    for t in test_reader:
        matrix = np.fromstring(','.join(t[1:]), dtype=float, sep=',')
        appname, cost = predict_app(dir_path / 'samples/training_data.csv', matrix)

        if appname == t[0]:
            true_positive += 1

    test_out.close()

    print('ACCURACY: {}%'.format((true_positive / total) * 100))

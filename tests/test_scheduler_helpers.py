from nextgenmap.scheduler import update_cbox_states


def test_update_cbox_states_parses_values():
    cb_states = [True] * 5
    cb_indices = [0] * 5

    update_cbox_states("5 10 * * 1", cb_states, cb_indices)

    assert cb_states == [True, True, True, True, True]
    assert cb_indices == [6, 11, 0, 0, 2]

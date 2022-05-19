import { AxiosRequestConfig } from 'axios';
import ListMovieCard from 'components/ListMovieCard';
import MovieFilter, { MovieFilterData } from 'components/MovieFilter';
import Pagination from 'components/Pagination';
import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Movie } from 'types/movie';
import { SpringPage } from 'types/spring';
import { requestBackend } from 'util/requests';
import MovieCard from '../../components/ReviewMovieCard';
import CardLoader from './CardLoader';
import './styles.css';

type ControlComponentsData = {
  activePage: number;
  filterData: MovieFilterData;
};

const MoviesList = () => {
  const [page, setPage] = useState<SpringPage<Movie>>();
  const [isLoading, setIsLoading] = useState(false);

  const [controlComponentsData, setControlComponentsData] =
    useState<ControlComponentsData>({
      activePage: 0,
      filterData: { name: '', genre: null },
    });

  // Muda a pagina, o filtro permanece
  const handlePageChange = (pageNumber: number) => {
    setControlComponentsData({
      activePage: pageNumber,
      filterData: controlComponentsData.filterData,
    });
  };

  // muda o filtro, pagina 0 e muda o filtro
  const handleSubmitFilter = (data: MovieFilterData) => {
    setControlComponentsData({
      activePage: 0,
      filterData: data,
    });
  };

  const getMovies = useCallback(() => {
    const config: AxiosRequestConfig = {
      method: 'GET',
      url: '/movies',
      withCredentials: true,
      params: {
        page: controlComponentsData.activePage,
        size: 4,
        name: controlComponentsData.filterData.name,
        genreId: controlComponentsData.filterData.genre?.id,
      },
    };

    requestBackend(config).then((response) => {
      setPage(response.data);
    });
  }, [controlComponentsData]);

  useEffect(() => {
    getMovies();
  }, [getMovies]);

  return (
    <div className="container my-4 movie-list-container">
      <div className="movie-list-search-container">
        <MovieFilter onSubmitFilter={handleSubmitFilter} />
      </div>

      <div className="movie-list-central">
        <div className="row justify-content-center">
          {isLoading ? (
            <CardLoader />
          ) : (
            page?.content.map((movie) => (
              <div
                className="col-sm-6 col-md-6 col-lg-6 col-xl-3 list-row-card-container"
                key={movie.id}
              >
                <Link to={'/movies/' + movie.id + '/reviews'} key={movie.id}>
                  <ListMovieCard movie={movie} />
                </Link>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="movie-list-pagination">
        <Pagination
          forcePage={page?.number}
          pageCount={page ? page.totalPages : 0}
          range={3}
          onChange={handlePageChange}
        />
      </div>
    </div>
  );
};

export default MoviesList;

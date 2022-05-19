import './styles.css';
import { Movie } from 'types/movie';
import { useEffect, useState } from 'react';
import { AxiosRequestConfig } from 'axios';
import { requestBackend } from 'util/requests';

type Props = {
  movieId: string;
};

const ReviewMovieCard = ({ movieId }: Props) => {
  const [movie, setMovie] = useState<Movie>();

  useEffect(() => {
    const config: AxiosRequestConfig = {
      method: 'GET',
      url: `/movies/${movieId}`,
      withCredentials: true,
    };

    requestBackend(config).then((response) => {
      setMovie(response.data);
    });
  }, [movieId]);

  return (
    <div className="movie-card">
      {movie ? (
        <div className="review-movie-card">
          <div className="review-movie-card-img-container">
            <img src={movie.imgUrl} alt={movie.title} />
          </div>
          <div className="review-movie-card-data-container">
            <h1 className="review-movie-card-h1_title">{movie.title}</h1>
            <h2 className="review-movie-card-h2_title">{movie.year}</h2>
            <p>
              {movie.subTitle ? movie.subTitle : '  '}
            </p>
            <div className="review-movie-card-sinopsis">
              <p>{movie.synopsis}</p>
            </div>
          </div>
        </div>
      ) : (
        <p>Não encontrado...</p>
      )}
    </div>
  );
};

export default ReviewMovieCard;
